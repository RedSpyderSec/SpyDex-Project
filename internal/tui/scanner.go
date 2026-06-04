package tui

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// AutomatorResult representa el hallazgo de un escaneo de seguridad o fuzzer
type AutomatorResult struct {
	ID         int
	Method     string
	URL        string
	Payload    string
	StatusCode int
	Length     int
	Issue      string
	Severity   string // "High", "Medium", "Low", "Info"
}

// Regexes para búsquedas pasivas de fugas de secretos
var (
	jwtRegex          = regexp.MustCompile(`eyJhbGciOi[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`)
	awsSecretKeyRegex = regexp.MustCompile(`(?i)aws(.{0,20})?(key|secret|token)(.{0,20})?['"][0-9a-zA-Z\/+]{40}['"]`)
	slackWebhookRegex = regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`)
	emailRegex        = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	ipRegex           = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	privateKeyRegex   = regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`)
)

// ActiveScanner realiza auditorías activas y fuzzing
type ActiveScanner struct {
	rawRequest string
	ctx        context.Context
	onProgress func(float64, string)
	onResult   func(AutomatorResult)
	client     *http.Client
}

func NewActiveScanner(raw string, ctx context.Context, onProgress func(float64, string), onResult func(AutomatorResult)) *ActiveScanner {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &ActiveScanner{
		rawRequest: raw,
		ctx:        ctx,
		onProgress: onProgress,
		onResult:   onResult,
		client: &http.Client{
			Timeout:   8 * time.Second,
			Transport: tr,
		},
	}
}

// RunVulnerabilityScan ejecuta pruebas automáticas de SQLi, XSS, Path Traversal y fugas de secretos
func (s *ActiveScanner) RunVulnerabilityScan() {
	s.onProgress(0.0, "Iniciando análisis de vulnerabilidades...")

	req, body, err := parseRawRequest(s.rawRequest)
	if err != nil {
		s.onProgress(1.0, fmt.Sprintf("Error parseando petición objetivo: %v", err))
		return
	}

	// 1. Análisis Pasivo
	s.onProgress(0.1, "Ejecutando análisis pasivo del request...")
	s.runPassiveChecks(req.Method, req.URL.String(), body)

	// Obtener parámetros editables
	queryParams := req.URL.Query()
	postParams, isForm := parseFormBody(req, body)

	totalParams := len(queryParams) + len(postParams)
	if totalParams == 0 {
		s.onProgress(0.5, "Sin parámetros query ni POST para pruebas activas.")
		s.onProgress(1.0, "Análisis de vulnerabilidades finalizado.")
		return
	}

	// Payloads de pruebas
	sqliPayloads := []string{"'", "\"", " OR 1=1--", "' OR '1'='1", "') OR ('1'='1"}
	xssPayloads := []string{"<script>alert(1)</script>", "\"><script>alert(1)</script>", "javascript:alert(1)", "<img src=x onerror=alert(1)>"}
	lfiPayloads := []string{"../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "/etc/passwd"}

	step := 0.8 / float64(totalParams)
	currentProgress := 0.1
	resultID := 1

	// Probar cada parámetro Query
	for paramName := range queryParams {
		s.onProgress(currentProgress, fmt.Sprintf("Auditando parámetro GET: %s...", paramName))

		// 1. SQL Injection
		for _, payload := range sqliPayloads {
			select {
			case <-s.ctx.Done():
				s.onProgress(currentProgress, "Escaneo cancelado por el usuario.")
				return
			default:
			}

			testVals := url.Values{}
			for k, v := range queryParams {
				testVals[k] = v
			}
			testVals.Set(paramName, payload)

			testReq, _ := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(body))
			copyHeaders(req.Header, testReq.Header)
			testReq.URL.RawQuery = testVals.Encode()

			resp, testRespBody, err := s.doRequest(testReq)
			if err != nil {
				continue
			}

			if detectSQLiError(testRespBody) {
				s.onResult(AutomatorResult{
					ID:         resultID,
					Method:     testReq.Method,
					URL:        testReq.URL.String(),
					Payload:    payload,
					StatusCode: resp.StatusCode,
					Length:     len(testRespBody),
					Issue:      fmt.Sprintf("Posible SQL Injection en GET [%s]", paramName),
					Severity:   "High",
				})
				resultID++
				break
			}
		}

		// 2. XSS (Reflected)
		for _, payload := range xssPayloads {
			select {
			case <-s.ctx.Done():
				return
			default:
			}

			testVals := url.Values{}
			for k, v := range queryParams {
				testVals[k] = v
			}
			testVals.Set(paramName, payload)

			testReq, _ := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(body))
			copyHeaders(req.Header, testReq.Header)
			testReq.URL.RawQuery = testVals.Encode()

			_, testRespBody, err := s.doRequest(testReq)
			if err != nil {
				continue
			}

			if strings.Contains(string(testRespBody), payload) {
				s.onResult(AutomatorResult{
					ID:         resultID,
					Method:     testReq.Method,
					URL:        testReq.URL.String(),
					Payload:    payload,
					StatusCode: 200,
					Length:     len(testRespBody),
					Issue:      fmt.Sprintf("XSS Reflejado en GET [%s]", paramName),
					Severity:   "Medium",
				})
				resultID++
				break
			}
		}

		// 3. Path Traversal
		for _, payload := range lfiPayloads {
			testVals := url.Values{}
			for k, v := range queryParams {
				testVals[k] = v
			}
			testVals.Set(paramName, payload)

			testReq, _ := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(body))
			copyHeaders(req.Header, testReq.Header)
			testReq.URL.RawQuery = testVals.Encode()

			_, testRespBody, err := s.doRequest(testReq)
			if err != nil {
				continue
			}

			if detectLFI(testRespBody) {
				s.onResult(AutomatorResult{
					ID:         resultID,
					Method:     testReq.Method,
					URL:        testReq.URL.String(),
					Payload:    payload,
					StatusCode: 200,
					Length:     len(testRespBody),
					Issue:      fmt.Sprintf("Path Traversal / LFI en GET [%s]", paramName),
					Severity:   "High",
				})
				resultID++
				break
			}
		}

		currentProgress += step
	}

	// Probar parámetros POST
	if isForm {
		for paramName := range postParams {
			s.onProgress(currentProgress, fmt.Sprintf("Auditando parámetro POST: %s...", paramName))

			// 1. SQL Injection en POST
			for _, payload := range sqliPayloads {
				select {
				case <-s.ctx.Done():
					return
				default:
				}

				testVals := url.Values{}
				for k, v := range postParams {
					testVals[k] = v
				}
				testVals.Set(paramName, payload)
				newBody := []byte(testVals.Encode())

				testReq, _ := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(newBody))
				copyHeaders(req.Header, testReq.Header)
				testReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))

				resp, testRespBody, err := s.doRequest(testReq)
				if err != nil {
					continue
				}

				if detectSQLiError(testRespBody) {
					s.onResult(AutomatorResult{
						ID:         resultID,
						Method:     testReq.Method,
						URL:        testReq.URL.String(),
						Payload:    payload,
						StatusCode: resp.StatusCode,
						Length:     len(testRespBody),
						Issue:      fmt.Sprintf("Posible SQL Injection en POST [%s]", paramName),
						Severity:   "High",
					})
					resultID++
					break
				}
			}

			// 2. XSS en POST
			for _, payload := range xssPayloads {
				select {
				case <-s.ctx.Done():
					return
				default:
				}

				testVals := url.Values{}
				for k, v := range postParams {
					testVals[k] = v
				}
				testVals.Set(paramName, payload)
				newBody := []byte(testVals.Encode())

				testReq, _ := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(newBody))
				copyHeaders(req.Header, testReq.Header)
				testReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))

				_, testRespBody, err := s.doRequest(testReq)
				if err != nil {
					continue
				}

				if strings.Contains(string(testRespBody), payload) {
					s.onResult(AutomatorResult{
						ID:         resultID,
						Method:     testReq.Method,
						URL:        testReq.URL.String(),
						Payload:    payload,
						StatusCode: 200,
						Length:     len(testRespBody),
						Issue:      fmt.Sprintf("XSS Reflejado en POST [%s]", paramName),
						Severity:   "Medium",
					})
					resultID++
					break
				}
			}

			currentProgress += step
		}
	}

	s.onProgress(1.0, "Análisis de vulnerabilidades finalizado con éxito.")
}

// RunPathDiscovery ejecuta fuerza bruta de rutas/directorios comunes sobre el host objetivo
func (s *ActiveScanner) RunPathDiscovery() {
	s.onProgress(0.0, "Iniciando descubrimiento de rutas (Path Discovery)...")

	req, _, err := parseRawRequest(s.rawRequest)
	if err != nil {
		s.onProgress(1.0, fmt.Sprintf("Error parseando petición objetivo: %v", err))
		return
	}

	baseURL := fmt.Sprintf("%s://%s", req.URL.Scheme, req.URL.Host)
	commonPaths := []string{
		"/admin", "/login", "/config.php", "/config.json", "/.git/HEAD",
		"/api", "/wp-admin", "/robots.txt", "/backup.zip", "/backup.sql",
		"/info.php", "/phpinfo", "/.env", "/setup", "/test", "/dev",
	}

	resultID := 1

	for idx, path := range commonPaths {
		select {
		case <-s.ctx.Done():
			s.onProgress(float64(idx)/float64(len(commonPaths)), "Path Discovery cancelado.")
			return
		default:
		}

		s.onProgress(float64(idx)/float64(len(commonPaths)), fmt.Sprintf("Probando ruta: %s...", path))
		targetURL := baseURL + path

		testReq, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}

		resp, body, err := s.doRequest(testReq)
		if err != nil {
			continue
		}

		if resp.StatusCode != 404 {
			severity := "Info"
			issue := fmt.Sprintf("Ruta descubierta: %s (Status: %d)", path, resp.StatusCode)
			if resp.StatusCode == 200 {
				if strings.Contains(path, ".env") || strings.Contains(path, "config") || strings.Contains(path, ".git") {
					severity = "High"
					issue = fmt.Sprintf("Fuga de archivo crítico en: %s", path)
				} else if strings.Contains(path, "admin") || strings.Contains(path, "backup") {
					severity = "Medium"
					issue = fmt.Sprintf("Ruta sensible expuesta: %s", path)
				} else {
					severity = "Low"
				}
			}

			s.onResult(AutomatorResult{
				ID:         resultID,
				Method:     "GET",
				URL:        targetURL,
				Payload:    path,
				StatusCode: resp.StatusCode,
				Length:     len(body),
				Issue:      issue,
				Severity:   severity,
			})
			resultID++
		}
	}

	s.onProgress(1.0, "Descubrimiento de rutas completado.")
}

func (s *ActiveScanner) runPassiveChecks(method, urlStr string, body []byte) {
	if len(body) == 0 {
		return
	}

	bodyStr := string(body)
	id := 900

	checks := []struct {
		regex    *regexp.Regexp
		issue    string
		severity string
	}{
		{jwtRegex, "Token JWT detectado en tráfico", "Info"},
		{awsSecretKeyRegex, "Clave de acceso AWS secreta expuesta", "High"},
		{slackWebhookRegex, "Webhook de Slack expuesto", "Medium"},
		{privateKeyRegex, "Clave privada SSL/SSH expuesta", "High"},
		{emailRegex, "Dirección de correo electrónico expuesta", "Info"},
	}

	for _, check := range checks {
		matches := check.regex.FindAllString(bodyStr, -1)
		for _, m := range matches {
			s.onResult(AutomatorResult{
				ID:         id,
				Method:     method,
				URL:        urlStr,
				Payload:    truncate(m, 30),
				StatusCode: 200,
				Length:     len(body),
				Issue:      check.issue,
				Severity:   check.severity,
			})
			id++
		}
	}
}

func (s *ActiveScanner) doRequest(req *http.Request) (*http.Response, []byte, error) {
	req.RequestURI = ""
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	return resp, body, nil
}

func copyHeaders(src, dst http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func parseFormBody(req *http.Request, body []byte) (url.Values, bool) {
	if req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		vals, err := url.ParseQuery(string(body))
		if err == nil {
			return vals, true
		}
	}
	return nil, false
}

func detectSQLiError(body []byte) bool {
	bodyStr := strings.ToLower(string(body))
	sqlErrors := []string{
		"you have an error in your sql syntax",
		"unclosed quotation mark after the character string",
		"sql server database error",
		"mysql_fetch_array()",
		"sqlite3::prepare()",
		"postgresql query failed",
		"ora-00933: sql command not properly ended",
	}
	for _, err := range sqlErrors {
		if strings.Contains(bodyStr, err) {
			return true
		}
	}
	return false
}

func detectLFI(body []byte) bool {
	bodyStr := string(body)
	lfiIndications := []string{
		"root:x:0:0:",
		"[boot loader]",
		"drivers/etc/hosts",
		"; for 16-bit app support",
	}
	for _, ind := range lfiIndications {
		if strings.Contains(bodyStr, ind) {
			return true
		}
	}
	return false
}
