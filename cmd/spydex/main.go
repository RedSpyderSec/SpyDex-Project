package main


import (
    "context"
    "flag"
    "fmt"
    "net/http"
    "os"
    "os/signal"
    "path/filepath"
    "syscall"
    "time"

    tea "github.com/charmbracelet/bubbletea"
    "spydex/ca"
    "spydex/internal/coordinator"
    "spydex/internal/history"
    "spydex/internal/proxy"
    "spydex/internal/tui"
)

func main() {
    addr := flag.String("addr", ":8080", "Dirección de escucha del proxy")

    defaultDBPath := "history.db"
    if homeDir, err := os.UserHomeDir(); err == nil {
        spydexDir := filepath.Join(homeDir, ".local", "share", "spydex")
        if err := os.MkdirAll(spydexDir, 0755); err == nil {
            defaultDBPath = filepath.Join(spydexDir, "history.db")
        }
    }

    dbPath := flag.String("db", defaultDBPath, "Ruta a la base de datos SQLite")
    caCertFile := flag.String("ca-cert", "ca.pem", "Fichero de certificado CA")
    caKeyFile := flag.String("ca-key", "ca.key", "Fichero de clave CA")
    flag.Parse()

    fmt.Fprintln(os.Stderr, "Iniciando SpyDex - Burp Suite en CLI...")

    // 1. Contexto para graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // 2. Cargar/generar CA para MITM
    caCert, err := ca.LoadOrGenerateCA(*caCertFile, *caKeyFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error cargando CA: %v\n", err)
        os.Exit(1)
    }

    // 3. Inicializar Coordinador
    coord := coordinator.NewCoordinator(ctx)
    defer coord.Stop()

    // 4. Inicializar Historial
    hist, err := history.NewHistoryManager(ctx, *dbPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error abriendo base de datos: %v\n", err)
        os.Exit(1)
    }
    defer hist.Close()
    hist.StartSaving(ctx, coord)

    // 5. Iniciar Proxy
    p := proxy.NewProxyServer(ctx, coord, *addr, caCert)
    proxyErrCh := p.Start(ctx)

    // 6. Iniciar TUI
    historyList, _ := hist.LoadAll(ctx)
    teaModel := tui.InitialModel(coord, historyList, hist)
    pProgram := tea.NewProgram(teaModel, tea.WithAltScreen())
    teaModel.SetSend(func(msg tea.Msg) {
        pProgram.Send(msg)
    })

    // 7. Enviar eventos a la TUI de forma asíncrona
    go func() {
        for {
            select {
            case tx, ok := <-coord.InterceptorChan:
                if !ok {
                    return
                }
                pProgram.Send(tui.InterceptMsg{Tx: tx})
            case <-ctx.Done():
                return
            }
        }
    }()

    go func() {
        for {
            select {
            case tx, ok := <-coord.HistoryChan:
                if !ok {
                    return
                }
                pProgram.Send(tui.HistoryMsg{Tx: tx})
            case <-ctx.Done():
                return
            }
        }
    }()

    // 8. Manejo de señales para graceful shutdown
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigCh
        fmt.Fprintln(os.Stderr, "\nSeñal recibida, apagando...")
        cancel() // cancela el contexto general

        // Apagar proxy graceful con timeout de 2 segundos para liberar goroutines
        shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
        defer shutdownCancel()
        if err := p.Shutdown(shutdownCtx); err != nil {
            fmt.Fprintf(os.Stderr, "Error apagando proxy: %v\n", err)
        }

        // Apagar TUI
        pProgram.Quit()
    }()

    // 9. Ejecutar TUI (bloqueante)
    if _, err := pProgram.Run(); err != nil {
        fmt.Fprintf(os.Stderr, "Error en TUI: %v\n", err)
        os.Exit(1)
    }

    // Esperar a que el proxy termine realmente
    // (el canal de error se cerrará al finalizar el servidor)
    select {
    case err := <-proxyErrCh:
        if err != nil && err != http.ErrServerClosed {
            fmt.Fprintf(os.Stderr, "Proxy terminó con error: %v\n", err)
        }
    case <-time.After(3 * time.Second):
        fmt.Fprintln(os.Stderr, "Tiempo de apagado del proxy expirado.")
    }

    fmt.Fprintln(os.Stderr, "SpyDex detenido.")
}
