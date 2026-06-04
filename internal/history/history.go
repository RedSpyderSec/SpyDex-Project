package history

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"spydex/internal/coordinator"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

type HistoryManager struct {
	db     *sqlx.DB
	cancel context.CancelFunc
}

func NewHistoryManager(ctx context.Context, dbPath string) (*HistoryManager, error) {
	db, err := sqlx.Connect("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	// Enable WAL mode and set busy timeout for concurrency
	_, _ = db.Exec("PRAGMA journal_mode=WAL;")
	_, _ = db.Exec("PRAGMA busy_timeout=5000;")

	// Database schema initialization
	schema := `
	CREATE TABLE IF NOT EXISTS transactions (
		id TEXT PRIMARY KEY,
		timestamp DATETIME,
		host TEXT,
		method TEXT,
		path TEXT,
		status_code INTEGER,
		duration_ms INTEGER,
		request_body BLOB,
		response_body BLOB,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_transactions_host ON transactions(host);
	CREATE INDEX IF NOT EXISTS idx_transactions_path ON transactions(path);
	`

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	h := &HistoryManager{db: db, cancel: cancel}

	return h, nil
}

// StartSaving lanza una goroutine que lee de HistoryChan y persiste.
func (h *HistoryManager) StartSaving(ctx context.Context, coordinator *coordinator.Coordinator) {
	go func() {
		for tx := range coordinator.HistoryChan {
			h.save(ctx, tx)
		}
	}()
}

func (h *HistoryManager) save(ctx context.Context, tx *coordinator.Transaction) {
	statusCode := 0
	if tx.Response != nil {
		statusCode = tx.Response.StatusCode
	}

	var reqBody, respBody []byte
	if tx.RequestBody != nil {
		reqBody = tx.RequestBody
	}
	if tx.ResponseBody != nil {
		respBody = tx.ResponseBody
	}

	const q = `
	INSERT OR REPLACE INTO transactions
		(id, timestamp, host, method, path, status_code, duration_ms, request_body, response_body)
	VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	// Write with timeout to ensure saving completes on shutdown
	writeCtx, writeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer writeCancel()

	if _, err := h.db.ExecContext(writeCtx, q,
		tx.ID,
		tx.Timestamp,
		tx.Host,
		tx.Method,
		tx.Path,
		statusCode,
		tx.Duration.Milliseconds(),
		reqBody,
		respBody,
	); err != nil {
		log.Printf("Error saving tx %s: %v", tx.ID, err)
	}
}

// Close cierra la DB.
func (h *HistoryManager) Close() error {
	h.cancel()
	return h.db.Close()
}

// LoadAll carga todas las transacciones históricas de la DB (sin los cuerpos pesados para ahorrar RAM).
func (h *HistoryManager) LoadAll(ctx context.Context) ([]*coordinator.Transaction, error) {
	var dbTxs []struct {
		ID           string    `db:"id"`
		Timestamp    time.Time `db:"timestamp"`
		Host         string    `db:"host"`
		Method       string    `db:"method"`
		Path         string    `db:"path"`
		StatusCode   int       `db:"status_code"`
		DurationMs   int64     `db:"duration_ms"`
	}

	query := `
	SELECT id, timestamp, host, method, path, status_code, duration_ms
	FROM transactions
	ORDER BY timestamp ASC;`

	err := h.db.SelectContext(ctx, &dbTxs, query)
	if err != nil {
		return nil, err
	}

	txs := make([]*coordinator.Transaction, len(dbTxs))
	for i, dbTx := range dbTxs {
		req, _ := http.NewRequest(dbTx.Method, "http://"+dbTx.Host+dbTx.Path, nil)
		if req == nil {
			req, _ = http.NewRequest("GET", "/", nil)
		}

		var resp *http.Response
		if dbTx.StatusCode > 0 {
			resp = &http.Response{
				StatusCode: dbTx.StatusCode,
				Header:     make(http.Header),
			}
		}

		txs[i] = &coordinator.Transaction{
			ID:           dbTx.ID,
			Timestamp:    dbTx.Timestamp,
			Host:         dbTx.Host,
			Method:       dbTx.Method,
			Path:         dbTx.Path,
			Request:      req,
			RequestBody:  nil, // Lazy loading: se carga al seleccionarlo en la TUI
			Response:     resp,
			ResponseBody: nil, // Lazy loading: se carga al seleccionarlo en la TUI
			Status:       coordinator.StatusForwarded, // default
			Duration:     time.Duration(dbTx.DurationMs) * time.Millisecond,
		}
	}

	return txs, nil
}

// GetBodies obtiene los cuerpos de petición y respuesta de una transacción específica.
func (h *HistoryManager) GetBodies(ctx context.Context, id string) (reqBody []byte, respBody []byte, err error) {
	var row struct {
		RequestBody  []byte `db:"request_body"`
		ResponseBody []byte `db:"response_body"`
	}
	query := `SELECT request_body, response_body FROM transactions WHERE id = ? LIMIT 1;`
	err = h.db.GetContext(ctx, &row, query, id)
	if err != nil {
		return nil, nil, err
	}
	return row.RequestBody, row.ResponseBody, nil
}

// ClearAll limpia todos los registros de la DB.
func (h *HistoryManager) ClearAll(ctx context.Context) error {
	_, err := h.db.ExecContext(ctx, "DELETE FROM transactions;")
	return err
}