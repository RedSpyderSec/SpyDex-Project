package coordinator

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

type TransactionStatus string

const (
	StatusPending   TransactionStatus = "Pending"
	StatusForwarded TransactionStatus = "Forwarded"
	StatusDropped   TransactionStatus = "Dropped"
	StatusModified  TransactionStatus = "Modified"
)

type ActionType string

const (
	ActionForward ActionType = "Forward"
	ActionDrop    ActionType = "Drop"
	ActionModify  ActionType = "Modify"
)

type Action struct {
	Type       ActionType
	ModifiedTx *Transaction
}

const (
	HTTP1_1 = "HTTP/1.1"
	HTTP2_0 = "HTTP/2.0"
)

// Transaction representa una petición/respuesta interceptada.
type Transaction struct {
	mu           sync.Mutex
	ID           string
	Timestamp    time.Time
	ClientAddr   string
	Method       string
	Host         string
	Path         string
	Request      *http.Request
	RequestBody  []byte
	Response     *http.Response
	ResponseBody []byte
	Status       TransactionStatus
	Duration     time.Duration
	Version      string
	WaitChan     chan Action // Canal para bloquear esta transacción hasta decisión de la TUI
}

func NewTransaction(req *http.Request) *Transaction {
	var body []byte
	if req.Body != nil {
		if req.ContentLength > 5*1024*1024 {
			body = []byte("[Cuerpo omitido: Mayor a 5MB]")
		} else {
			body, _ = io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	version := HTTP1_1
	if req.ProtoAtLeast(2, 0) {
		version = HTTP2_0
	}

	return &Transaction{
		ID:          time.Now().Format("20060102150405.999999999"),
		Timestamp:   time.Now(),
		ClientAddr:  req.RemoteAddr,
		Method:      req.Method,
		Host:        req.Host,
		Path:        req.URL.Path,
		Request:     req,
		RequestBody: body,
		Status:      StatusPending,
		Version:     version,
		WaitChan:    make(chan Action, 1), // buffered 1 para no bloquear al enviador
	}
}

type Coordinator struct {
	InterceptorChan  chan *Transaction
	HistoryChan      chan *Transaction
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	interceptEnabled bool
	mu               sync.RWMutex
}

func NewCoordinator(ctx context.Context) *Coordinator {
	ctx, cancel := context.WithCancel(ctx)
	return &Coordinator{
		InterceptorChan:  make(chan *Transaction, 100),
		HistoryChan:      make(chan *Transaction, 100),
		cancel:           cancel,
		interceptEnabled: true,
	}
}

func (c *Coordinator) IsInterceptEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.interceptEnabled
}

func (c *Coordinator) SetInterceptEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.interceptEnabled = enabled
}

// Stop cierra los canales y espera a que las goroutines terminen.
func (c *Coordinator) Stop() {
	c.cancel()
	close(c.InterceptorChan)
	close(c.HistoryChan)
	c.wg.Wait()
}