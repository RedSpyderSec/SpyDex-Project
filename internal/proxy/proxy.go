package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/elazarl/goproxy"
	"spydex/internal/coordinator"
)

type ProxyServer struct {
	httpServer *http.Server
	proxy      *goproxy.ProxyHttpServer
	coord      *coordinator.Coordinator
}

func NewProxyServer(ctx context.Context, coord *coordinator.Coordinator, addr string, caCert *tls.Certificate) *ProxyServer {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.Logger = log.New(io.Discard, "", 0)

	// MITM con CA propia, como en customca/main.go de goproxy
	customCaMitm := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(caCert),
	}
	var customAlwaysMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return customCaMitm, host
	}

	proxy.OnRequest().HandleConnect(customAlwaysMitm)

	ps := &ProxyServer{
		proxy: proxy,
		coord: coord,
	}

	// Interceptor de Requests
	proxy.OnRequest().DoFunc(func(req *http.Request, pCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		tx := coordinator.NewTransaction(req)

		if !ps.coord.IsInterceptEnabled() {
			tx.Status = coordinator.StatusForwarded
			pCtx.UserData = tx
			return req, nil
		}

		start := time.Now()
		// Enviar a la TUI para decisión
		ps.coord.InterceptorChan <- tx

		// Bloquear hasta que la TUI responda o el servidor se detenga (evitar cuelgues al apagar)
		var action coordinator.Action
		select {
		case action = <-tx.WaitChan:
		case <-ctx.Done():
			action = coordinator.Action{Type: coordinator.ActionForward, ModifiedTx: tx}
		}
		tx.Duration = time.Since(start)

		switch action.Type {
		case coordinator.ActionDrop:
			tx.Status = coordinator.StatusDropped
			ps.coord.HistoryChan <- tx
			return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, 403, "Forbidden")
		case coordinator.ActionForward:
			tx.Status = coordinator.StatusForwarded
			req = action.ModifiedTx.Request
		case coordinator.ActionModify:
			tx.Status = coordinator.StatusModified
			req = action.ModifiedTx.Request
		}

		pCtx.UserData = tx
		return req, nil
	})

	// Interceptor de Responses
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if tx, ok := ctx.UserData.(*coordinator.Transaction); ok {
			tx.Response = resp
			if resp != nil && resp.Body != nil {
				if resp.ContentLength > 5*1024*1024 {
					tx.ResponseBody = []byte("[Cuerpo omitido: Mayor a 5MB]")
				} else {
					body, _ := io.ReadAll(resp.Body)
					tx.ResponseBody = body
					resp.Body = io.NopCloser(bytes.NewBuffer(body))
				}
			}
			ps.coord.HistoryChan <- tx
		}
		return resp
	})

	// Configurar servidor HTTP con timeouts
	ps.httpServer = &http.Server{
		Addr:    addr,
		Handler: proxy,
		TLSConfig: &tls.Config{
			// No usamos InsecureSkipVerify aquí; la CA se maneja vía goproxy
			MinVersion: tls.VersionTLS12,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return ps
}

// Start lanza el proxy en una goroutine y devuelve un canal de error.
func (ps *ProxyServer) Start(ctx context.Context) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		ln, err := net.Listen("tcp", ps.httpServer.Addr)
		if err != nil {
			errCh <- fmt.Errorf("proxy listen: %w", err)
			return
		}

		// Para producción, podrías usar TLS listener si quieres que los clientes
		// se conecten al proxy por TLS. Aquí dejamos TCP normal porque el proxy
		// es HTTP y el MITM se hace con CONNECT.
		fmt.Fprintf(os.Stderr, "Proxy listening on %s\n", ps.httpServer.Addr)

		if err := ps.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("proxy serve: %w", err)
		}
	}()
	return errCh
}

// Shutdown apaga el proxy de forma graceful.
func (ps *ProxyServer) Shutdown(ctx context.Context) error {
	return ps.httpServer.Shutdown(ctx)
}