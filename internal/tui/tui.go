package tui

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"spydex/internal/coordinator"
	"spydex/internal/history"
)

// InterceptMsg se envía a la TUI cuando se intercepta una petición
type InterceptMsg struct {
	Tx *coordinator.Transaction
}

// HistoryMsg se envía a la TUI cuando una petición pasa al historial
type HistoryMsg struct {
	Tx *coordinator.Transaction
}

// repeaterResultMsg se envía a la TUI cuando finaliza un reenvío
type repeaterResultMsg struct {
	slot  int
	text  string
	audit string
	err   error
}

// Styles
var (
	accentColor = lipgloss.Color("#00d7ff") // Cyan eléctrico (Modo Comando)
	purpleColor = lipgloss.Color("#d700ff") // Magenta/Morado (Modo Edición)
	grayColor   = lipgloss.Color("#585858")
	borderColor = lipgloss.Color("#303030")

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#121212")).
			Background(accentColor).
			Padding(0, 2).
			MarginBottom(1)

	highlight = lipgloss.NewStyle().Bold(true).Foreground(accentColor)

	tabActiveStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(accentColor).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(accentColor).
			Padding(0, 1)

	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(grayColor).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(borderColor).
				Padding(0, 1)

	focusedPanelStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(accentColor).
				Padding(0, 1)

	unfocusedPanelStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(borderColor).
				Padding(0, 1)

	selectedRowStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#262626")).
				Foreground(accentColor).
				Bold(true)

	normalRowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#EEEEEE"))

	footerStyle = lipgloss.NewStyle().
			Foreground(grayColor).
			Italic(true)

	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff66")).Bold(true)
	dangerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff3366")).Bold(true)

	// Severity styles
	greenColor  = lipgloss.Color("#00ff66")
	orangeColor = lipgloss.Color("#ff9900")
	redColor    = lipgloss.Color("#ff3366")
	blueColor   = lipgloss.Color("#0099ff")

	severityHighStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#ffffff")).
				Background(redColor).
				Padding(0, 1)

	severityMediumStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#ffffff")).
				Background(orangeColor).
				Padding(0, 1)

	severityLowStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#ffffff")).
				Background(blueColor).
				Padding(0, 1)

	severityInfoStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#ffffff")).
				Background(grayColor).
				Padding(0, 1)
)

type RepeaterSlot struct {
	RequestArea  textarea.Model
	ResponseView viewport.Model
	Focused      int // 0 = Request, 1 = Response
	ResponseRaw  string
	ResponseAudit string
	Loading      bool
}

type Model struct {
	coordinator    *coordinator.Coordinator
	pendingTx      []*coordinator.Transaction
	historyTx      []*coordinator.Transaction
	selectedIndex  int // para Intercept
	historyIdx     int // para History
	activeTab      int // 0 = Intercept, 1 = History, 2 = Repeater, 3 = Decoder, 4 = Automator

	// Focus states (splits)
	// Para Intercept y History: 0 = Lista enfocada, 1 = Viewport enfocado
	interceptFocus int
	historyFocus   int
	historySubTab  int // 0 = Request, 1 = Response (para el panel de detalles)

	// Viewports para detalles
	interceptVp viewport.Model
	historyVp   viewport.Model
	sitemapVp   viewport.Model

	// Sitemap interactivo
	sitemapDomainIdx int
	sitemapRowIdx    int

	// Intercept Editor
	interceptEditing bool
	interceptTa      textarea.Model

	// Repeater
	repeaterSlots   []*RepeaterSlot
	activeSlot      int
	repeaterEditing bool

	// Decoder
	decoderInput   textarea.Model
	decoderVp      viewport.Model
	decoderEditing bool

	heightOffset int

	// Send callback to communicate with bubble tea loop asynchronously
	Send func(tea.Msg)

	// Automator / Scanner / Intruder
	automatorRequest   string
	automatorResults   []AutomatorResult
	automatorRunning   bool
	automatorScanType  int // 0 = Vulnerability Scan, 1 = Path Discovery
	automatorProgress  float64
	automatorLog       []string
	automatorCancel    context.CancelFunc

	width, height int
	ready         bool

	historyManager *history.HistoryManager
	exitConfirm    bool
}

// Mensajes del escáner asíncrono
type automatorProgressMsg struct {
	Progress float64
	Log      string
}

type automatorResultMsg struct {
	Result AutomatorResult
}

type automatorFinishedMsg struct {
	Log string
}

func (m *Model) SetSend(send func(tea.Msg)) {
	m.Send = send
}

func InitialModel(coord *coordinator.Coordinator, historyList []*coordinator.Transaction, histMgr *history.HistoryManager) *Model {
	// Configurar viewports de detalles
	intVp := viewport.New(0, 0)
	histVp := viewport.New(0, 0)

	// Configurar slots de Repeater
	slots := make([]*RepeaterSlot, 3)
	for i := 0; i < 3; i++ {
		ta := textarea.New()
		ta.Placeholder = "Raw HTTP request...\nExample:\nGET / HTTP/1.1\nHost: host.com\n\n"
		ta.SetHeight(15)
		ta.SetWidth(40)
		ta.Blur() // Iniciar sin foco por defecto (Modo Comando)

		vp := viewport.New(0, 0)

		slots[i] = &RepeaterSlot{
			RequestArea:  ta,
			ResponseView: vp,
			Focused:      0,
		}
	}

	// Configurar Decoder
	decTa := textarea.New()
	decTa.Placeholder = "Write or paste text to encode/decode..."
	decTa.SetHeight(5)
	decTa.Blur() // Iniciar sin foco por defecto

	decVp := viewport.New(0, 0)
	siteVp := viewport.New(0, 0)

	intTa := textarea.New()
	intTa.Placeholder = "Edit raw request headers/body here..."
	intTa.SetHeight(15)
	intTa.SetWidth(40)
	intTa.Blur() // Iniciar sin foco por defecto

	m := &Model{
		coordinator:      coord,
		pendingTx:        make([]*coordinator.Transaction, 0),
		historyTx:        historyList,
		selectedIndex:    0,
		historyIdx:       len(historyList) - 1,
		activeTab:        0,
		interceptVp:      intVp,
		historyVp:        histVp,
		sitemapVp:        siteVp,
		interceptEditing: false,
		interceptTa:      intTa,
		repeaterSlots:    slots,
		activeSlot:       0,
		repeaterEditing:  false,
		decoderInput:     decTa,
		decoderVp:        decVp,
		decoderEditing:   false,
		automatorLog:     []string{"Inactivo. Envía una petición para comenzar."},
		historyManager:   histMgr,
		exitConfirm:      false,
	}
	m.updateSitemapContent()
	return m
}

func (m *Model) Init() tea.Cmd {
	return nil
}

func (m *Model) blurAllInputs() {
	m.interceptEditing = false
	m.interceptTa.Blur()
	m.repeaterEditing = false
	for _, slot := range m.repeaterSlots {
		slot.RequestArea.Blur()
	}
	m.decoderEditing = false
	m.decoderInput.Blur()
}

func (m *Model) sendActiveRepeaterRequest() tea.Cmd {
	slot := m.repeaterSlots[m.activeSlot]
	if !slot.Loading {
		slot.Loading = true
		slot.ResponseView.SetContent("Enviando petición a servidor...")
		rawReq := slot.RequestArea.Value()
		return doRepeaterRequest(m.activeSlot, rawReq)
	}
	return nil
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Quitar ejecución global
		if m.exitConfirm {
			switch msg.String() {
			case "y", "Y":
				// Guardar DB y Salir (comportamiento normal)
				return m, tea.Quit
			case "n", "N":
				// Limpiar base de datos y salir
				if m.historyManager != nil {
					_ = m.historyManager.ClearAll(context.Background())
				}
				return m, tea.Quit
			default:
				// Cancelar y volver al TUI
				m.exitConfirm = false
				return m, nil
			}
		}

		if msg.String() == "ctrl+c" {
			m.exitConfirm = true
			return m, nil
		}

		// Determinar si estamos en Modo Inserción/Edición en la pestaña activa
		isInserting := false
		switch m.activeTab {
		case 0:
			isInserting = m.interceptEditing
		case 2:
			isInserting = m.repeaterEditing
		case 3:
			isInserting = m.decoderEditing
		}

		if isInserting {
			// --- MODO EDICIÓN / INSERCIÓN ---
			switch msg.String() {
			case "esc":
				// Volver a Modo Comando
				switch m.activeTab {
				case 0:
					m.interceptEditing = false
					m.interceptTa.Blur()
				case 2:
					m.repeaterEditing = false
					m.repeaterSlots[m.activeSlot].RequestArea.Blur()
				case 3:
					m.decoderEditing = false
					m.decoderInput.Blur()
				}
				return m, nil

			case "ctrl+s":
				if m.activeTab == 0 {
					if m.saveEditedInterceptRequest() {
						m.interceptEditing = false
						m.interceptTa.Blur()
					}
					return m, nil
				} else if m.activeTab == 2 {
					cmd := m.sendActiveRepeaterRequest()
					if cmd != nil {
						cmds = append(cmds, cmd)
					}
					// Volver a Modo Comando al enviar
					m.repeaterEditing = false
					m.repeaterSlots[m.activeSlot].RequestArea.Blur()
					return m, tea.Batch(cmds...)
				}

			case "ctrl+f":
				if m.activeTab == 0 {
					if m.saveEditedInterceptRequest() {
						m.forwardInterceptedRequest()
					}
					return m, nil
				}
			}

			// Pasar el evento al área de texto activa
			var cmd tea.Cmd
			switch m.activeTab {
			case 0:
				m.interceptTa, cmd = m.interceptTa.Update(msg)
				cmds = append(cmds, cmd)
			case 2:
				slot := m.repeaterSlots[m.activeSlot]
				slot.RequestArea, cmd = slot.RequestArea.Update(msg)
				cmds = append(cmds, cmd)
			case 3:
				m.decoderInput, cmd = m.decoderInput.Update(msg)
				cmds = append(cmds, cmd)
				m.updateDecoderOutput()
			}
			return m, tea.Batch(cmds...)
		}

		// --- MODO COMANDO ---
		switch msg.String() {
		// Cambiar de Pestaña Principal (1-5)
		case "1":
			m.activeTab = 0
			m.blurAllInputs()
			m.updateAllDetails()
			return m, nil
		case "2":
			m.activeTab = 1
			m.blurAllInputs()
			m.updateAllDetails()
			return m, nil
		case "3":
			m.activeTab = 2
			m.blurAllInputs()
			return m, nil
		case "4":
			m.activeTab = 3
			m.blurAllInputs()
			m.updateDecoderOutput()
			return m, nil
		case "5":
			m.activeTab = 4
			m.blurAllInputs()
			return m, nil

		case "alt+up", "ctrl+up":
			m.heightOffset++
			m.resizeViewports()
			return m, nil

		case "alt+down", "ctrl+down":
			if m.heightOffset > 0 {
				m.heightOffset--
				m.resizeViewports()
			}
			return m, nil

		case "tab":
			// Navegación de foco dentro de la pestaña en Modo Comando
			switch m.activeTab {
			case 0: // Intercept
				m.interceptFocus = 1 - m.interceptFocus
			case 1: // History
				m.historyFocus = (m.historyFocus + 1) % 4 // 0 = Lista, 1 = Sitemap, 2 = Sub-Tab Request/Response, 3 = Detalle Viewport
			case 2: // Repeater
				slot := m.repeaterSlots[m.activeSlot]
				slot.Focused = 1 - slot.Focused
			}
			return m, nil

		case "r", "R":
			// Enviar petición al Repeater
			var txToCopy *coordinator.Transaction
			if m.activeTab == 0 && len(m.pendingTx) > 0 {
				txToCopy = m.pendingTx[m.selectedIndex]
			} else if m.activeTab == 1 && len(m.historyTx) > 0 && m.historyIdx >= 0 && m.historyIdx < len(m.historyTx) {
				txToCopy = m.historyTx[m.historyIdx]
			}

			if txToCopy != nil {
				raw := formatRawRequest(txToCopy)
				slot := m.repeaterSlots[m.activeSlot]
				slot.RequestArea.SetValue(raw)
				slot.ResponseRaw = ""
				slot.ResponseView.SetContent("Petición copiada al Repeater. Presiona 'e' o 'Enter' para editar, o 'Ctrl+S' para enviar.")
				m.activeTab = 2
				slot.Focused = 0
				m.repeaterEditing = false
				slot.RequestArea.Blur()
			}
			return m, nil

		case "y", "Y":
			// Enviar contenido (body o texto) seleccionado al Decoder
			var contentToDecode string
			switch m.activeTab {
			case 0: // Intercept
				if len(m.pendingTx) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.pendingTx) {
					tx := m.pendingTx[m.selectedIndex]
					contentToDecode = string(tx.RequestBody)
					if contentToDecode == "" {
						contentToDecode = formatRawRequest(tx) // fallback a raw request
					}
				}
			case 1: // History
				if len(m.historyTx) > 0 && m.historyIdx >= 0 && m.historyIdx < len(m.historyTx) {
					tx := m.historyTx[m.historyIdx]
					if m.historySubTab == 0 {
						contentToDecode = string(tx.RequestBody)
						if contentToDecode == "" {
							contentToDecode = formatRawRequest(tx)
						}
					} else {
						contentToDecode = string(tx.ResponseBody)
					}
				}
			case 2: // Repeater
				slot := m.repeaterSlots[m.activeSlot]
				if slot.Focused == 0 {
					contentToDecode = slot.RequestArea.Value()
				} else {
					contentToDecode = slot.ResponseRaw
				}
			}

			if contentToDecode != "" {
				m.decoderInput.SetValue(contentToDecode)
				m.activeTab = 3 // Cambiar a pestaña Decoder
				m.blurAllInputs()
				m.updateDecoderOutput()
			}
			return m, nil

		case "a", "A":
			// Enviar petición al Automator
			var txToCopy *coordinator.Transaction
			if m.activeTab == 0 && len(m.pendingTx) > 0 {
				txToCopy = m.pendingTx[m.selectedIndex]
			} else if m.activeTab == 1 && len(m.historyTx) > 0 && m.historyIdx >= 0 && m.historyIdx < len(m.historyTx) {
				txToCopy = m.historyTx[m.historyIdx]
			}

			if txToCopy != nil {
				raw := formatRawRequest(txToCopy)
				m.automatorRequest = raw
				m.automatorResults = nil
				m.automatorProgress = 0.0
				m.automatorLog = []string{"Petición recibida en Automator. Presiona 's' para escanear."}
				m.activeTab = 4 // Cambiar a pestaña Automator
				m.blurAllInputs()
			}
			return m, nil

		case "i", "I":
			// Alternar interceptación general (MITM) de forma global
			current := m.coordinator.IsInterceptEnabled()
			m.coordinator.SetInterceptEnabled(!current)
			return m, nil

		// Entrar a Modo Inserción/Edición
		case "e", "E", "enter":
			switch m.activeTab {
			case 0: // Intercept
				if len(m.pendingTx) > 0 {
					tx := m.pendingTx[m.selectedIndex]
					raw := formatRawRequest(tx)
					m.interceptTa.SetValue(raw)
					m.interceptEditing = true
					m.interceptTa.Focus()
					return m, textarea.Blink
				}
			case 2: // Repeater
				slot := m.repeaterSlots[m.activeSlot]
				if slot.Focused == 0 {
					m.repeaterEditing = true
					slot.RequestArea.Focus()
					return m, textarea.Blink
				}
			case 3: // Decoder
				m.decoderEditing = true
				m.decoderInput.Focus()
				return m, textarea.Blink
			}
		}

		// Atajos específicos por pestaña en Modo Comando
		switch m.activeTab {
		case 0:
			m.handleInterceptCommandKeys(msg.String())
		case 1:
			m.handleHistoryCommandKeys(msg.String())
		case 2:
			cmd := m.handleRepeaterCommandKeys(msg.String())
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		case 4:
			cmd := m.handleAutomatorCommandKeys(msg.String())
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		m.resizeViewports()

	case InterceptMsg:
		m.pendingTx = append(m.pendingTx, msg.Tx)
		if len(m.pendingTx) == 1 {
			m.selectedIndex = 0
			m.updateInterceptDetail()
		}

	case HistoryMsg:
		// Evitar duplicados actualizando el registro existente si coincide el ID
		idx := -1
		for i, t := range m.historyTx {
			if t.ID == msg.Tx.ID {
				idx = i
				break
			}
		}
		if idx != -1 {
			m.historyTx[idx] = msg.Tx
		} else {
			m.historyTx = append(m.historyTx, msg.Tx)
			if len(m.historyTx) == 1 {
				m.historyIdx = 0
			} else if m.historyIdx == len(m.historyTx)-2 {
				m.historyIdx = len(m.historyTx) - 1 // auto-scroll al final
			}
		}
		m.updateHistoryDetail()
		m.updateSitemapContent()

	case repeaterResultMsg:
		slot := m.repeaterSlots[msg.slot]
		slot.Loading = false
		if msg.err != nil {
			slot.ResponseRaw = fmt.Sprintf("Error enviando petición:\n%v", msg.err)
			slot.ResponseAudit = ""
		} else {
			slot.ResponseRaw = msg.text
			slot.ResponseAudit = msg.audit
		}
		slot.ResponseView.SetContent(slot.ResponseRaw)
		m.resizeViewports()

	case automatorProgressMsg:
		m.automatorProgress = msg.Progress
		m.automatorLog = append(m.automatorLog, msg.Log)
		return m, nil

	case automatorResultMsg:
		m.automatorResults = append(m.automatorResults, msg.Result)
		m.automatorLog = append(m.automatorLog, fmt.Sprintf("[!] Hallazgo [%s]: %s", msg.Result.Severity, msg.Result.Issue))
		return m, nil

	case automatorFinishedMsg:
		m.automatorRunning = false
		m.automatorProgress = 1.0
		m.automatorLog = append(m.automatorLog, msg.Log)
		return m, nil
	}

	// Propagar scrolls y redibujado de viewports en Modo Comando
	if m.ready {
		// Siempre propagar eventos que no sean teclas (ej. WindowSizeMsg, TickMsg) a todos los viewports principales
		_, isKey := msg.(tea.KeyMsg)

		// Viewport Intercept
		if !isKey || (m.activeTab == 0 && m.interceptFocus == 1 && !m.interceptEditing) {
			var cmd tea.Cmd
			m.interceptVp, cmd = m.interceptVp.Update(msg)
			cmds = append(cmds, cmd)
		}
		// Viewport History Detail
		if !isKey || (m.activeTab == 1 && m.historyFocus == 3) {
			var cmd tea.Cmd
			m.historyVp, cmd = m.historyVp.Update(msg)
			cmds = append(cmds, cmd)
		}
		// Viewport Sitemap
		if !isKey || (m.activeTab == 1 && m.historyFocus == 1) {
			var cmd tea.Cmd
			m.sitemapVp, cmd = m.sitemapVp.Update(msg)
			cmds = append(cmds, cmd)
		}
		// Viewport Repeater
		if !isKey || (m.activeTab == 2 && m.repeaterSlots[m.activeSlot].Focused == 1) {
			var cmd tea.Cmd
			m.repeaterSlots[m.activeSlot].ResponseView, cmd = m.repeaterSlots[m.activeSlot].ResponseView.Update(msg)
			cmds = append(cmds, cmd)
		}
		// Viewport Decoder
		if !isKey || m.activeTab == 3 {
			var cmd tea.Cmd
			m.decoderVp, cmd = m.decoderVp.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

// --- Manejo de Teclado Específico en Modo Comando ---

func (m *Model) handleInterceptCommandKeys(key string) {
	if m.interceptFocus == 0 { // Lista enfocada
		switch key {
		case "up", "k":
			if m.selectedIndex > 0 {
				m.selectedIndex--
				m.updateInterceptDetail()
			}
		case "down", "j":
			if m.selectedIndex < len(m.pendingTx)-1 {
				m.selectedIndex++
				m.updateInterceptDetail()
			}
		case "f", "F": // Forward
			m.forwardInterceptedRequest()
		case "d", "D": // Drop
			if len(m.pendingTx) > 0 {
				tx := m.pendingTx[m.selectedIndex]
				tx.WaitChan <- coordinator.Action{Type: coordinator.ActionDrop}
				m.pendingTx = append(m.pendingTx[:m.selectedIndex], m.pendingTx[m.selectedIndex+1:]...)
				if m.selectedIndex >= len(m.pendingTx) && m.selectedIndex > 0 {
					m.selectedIndex--
				}
				m.updateInterceptDetail()
			}
		}
	}
}

func (m *Model) saveEditedInterceptRequest() bool {
	if len(m.pendingTx) == 0 || m.selectedIndex < 0 || m.selectedIndex >= len(m.pendingTx) {
		return false
	}
	tx := m.pendingTx[m.selectedIndex]
	req, body, err := parseRawRequest(m.interceptTa.Value())
	if err != nil {
		m.interceptVp.SetContent(fmt.Sprintf("[!] Error de parseo de petición:\n%v\n\nCorrige el formato HTTP para poder continuar.", err))
		return false
	}
	tx.Request = req
	tx.RequestBody = body
	tx.Method = req.Method
	tx.Host = req.Host
	tx.Path = req.URL.Path
	m.updateInterceptDetail()
	return true
}

func (m *Model) forwardInterceptedRequest() {
	if len(m.pendingTx) == 0 || m.selectedIndex < 0 || m.selectedIndex >= len(m.pendingTx) {
		return
	}
	tx := m.pendingTx[m.selectedIndex]
	tx.WaitChan <- coordinator.Action{Type: coordinator.ActionForward, ModifiedTx: tx}
	m.pendingTx = append(m.pendingTx[:m.selectedIndex], m.pendingTx[m.selectedIndex+1:]...)
	if m.selectedIndex >= len(m.pendingTx) && m.selectedIndex > 0 {
		m.selectedIndex--
	}
	m.interceptEditing = false
	m.updateInterceptDetail()
}

func parseRawRequest(raw string) (*http.Request, []byte, error) {
	// Separar cabeceras y cuerpo de la petición cruda para cálculo dinámico del cuerpo
	parts := strings.SplitN(raw, "\n\n", 2)
	if len(parts) == 1 {
		parts = strings.SplitN(raw, "\r\n\r\n", 2)
	}

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return nil, nil, err
	}

	var body []byte
	if len(parts) > 1 {
		body = []byte(parts[1])
	}

	// Re-calcular Content-Length dinámicamente si el cuerpo ha cambiado
	if len(body) > 0 {
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		req.ContentLength = int64(len(body))
		req.Body = io.NopCloser(bytes.NewReader(body))
	} else {
		req.Header.Del("Content-Length")
		req.ContentLength = 0
		req.Body = http.NoBody
	}

	// Completar URL y Host para cliente HTTP
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if req.URL.Scheme == "" {
		if strings.Contains(req.URL.Host, ":443") {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}
	}

	return req, body, nil
}

func (m *Model) handleHistoryCommandKeys(key string) {
	if m.historyFocus == 0 { // Lista enfocada
		switch key {
		case "up", "k":
			if m.historyIdx > 0 {
				m.historyIdx--
				m.updateHistoryDetail()
			}
		case "down", "j":
			if m.historyIdx < len(m.historyTx)-1 {
				m.historyIdx++
				m.updateHistoryDetail()
			}
		}
	} else if m.historyFocus == 1 { // Sitemap enfocado
		host, rows := m.getSitemapRows()
		switch key {
		case "left", "h":
			if m.sitemapDomainIdx > 0 {
				m.sitemapDomainIdx--
				m.sitemapRowIdx = 0
				m.updateSitemapContent()
			}
		case "right", "l":
			hostsMap := make(map[string]bool)
			for _, tx := range m.historyTx {
				if tx.Host != "" {
					hostsMap[tx.Host] = true
				}
			}
			var hosts []string
			for k := range hostsMap {
				hosts = append(hosts, k)
			}
			sort.Strings(hosts)
			if m.sitemapDomainIdx < len(hosts)-1 {
				m.sitemapDomainIdx++
				m.sitemapRowIdx = 0
				m.updateSitemapContent()
			}
		case "up", "k":
			if m.sitemapRowIdx > 0 {
				m.sitemapRowIdx--
				m.updateSitemapContent()
			}
		case "down", "j":
			if m.sitemapRowIdx < len(rows)-1 {
				m.sitemapRowIdx++
				m.updateSitemapContent()
			}
		case "enter":
			if len(rows) > 0 && m.sitemapRowIdx >= 0 && m.sitemapRowIdx < len(rows) {
				path := rows[m.sitemapRowIdx].path
				foundIdx := findMatchingTxIndex(m.historyTx, host, path)
				if foundIdx != -1 {
					m.historyIdx = foundIdx
					m.updateHistoryDetail()
				}
			}
		}
	} else if m.historyFocus == 2 { // Selector de Sub-pestaña (Request / Response)
		switch key {
		case "left", "right", "h", "l":
			m.historySubTab = 1 - m.historySubTab
			m.updateHistoryDetail()
		}
	}
}

func (m *Model) handleRepeaterCommandKeys(key string) tea.Cmd {
	switch key {
	case "[": // Slot anterior
		if m.activeSlot > 0 {
			m.activeSlot--
		}
	case "]": // Slot siguiente
		if m.activeSlot < len(m.repeaterSlots)-1 {
			m.activeSlot++
		}
	case "ctrl+s": // Enviar Petición
		return m.sendActiveRepeaterRequest()
	}
	return nil
}

func (m *Model) handleAutomatorCommandKeys(key string) tea.Cmd {
	switch key {
	case "s", "S":
		if m.automatorRunning {
			if m.automatorCancel != nil {
				m.automatorCancel()
			}
			m.automatorRunning = false
			m.automatorLog = append(m.automatorLog, "Escaneo detenido por el usuario.")
			return nil
		} else {
			return m.startAutomatorScan()
		}
	case "p", "P":
		if !m.automatorRunning {
			m.automatorScanType = 1 - m.automatorScanType
			m.automatorResults = nil
			m.automatorProgress = 0.0
			m.automatorLog = []string{fmt.Sprintf("Tipo de escaneo cambiado a: %d", m.automatorScanType)}
		}
	case "c", "C":
		if !m.automatorRunning {
			m.automatorRequest = ""
			m.automatorResults = nil
			m.automatorProgress = 0.0
			m.automatorLog = []string{"Automator limpiado."}
		}
	case "i", "I":
		// Alternar interceptación general
		current := m.coordinator.IsInterceptEnabled()
		m.coordinator.SetInterceptEnabled(!current)
	}
	return nil
}

func (m *Model) startAutomatorScan() tea.Cmd {
	if m.automatorRequest == "" {
		return nil
	}
	m.automatorRunning = true
	m.automatorResults = nil
	m.automatorProgress = 0.0
	m.automatorLog = []string{"Iniciando escaneo..."}

	ctx, cancel := context.WithCancel(context.Background())
	m.automatorCancel = cancel

	raw := m.automatorRequest
	scanType := m.automatorScanType
	send := m.Send

	return func() tea.Msg {
		go func() {
			onProgress := func(prog float64, logStr string) {
				if send != nil {
					send(automatorProgressMsg{Progress: prog, Log: logStr})
				}
			}
			onResult := func(res AutomatorResult) {
				if send != nil {
					send(automatorResultMsg{Result: res})
				}
			}

			scanner := NewActiveScanner(raw, ctx, onProgress, onResult)
			if scanType == 0 {
				scanner.RunVulnerabilityScan()
			} else {
				scanner.RunPathDiscovery()
			}
			if send != nil {
				send(automatorFinishedMsg{Log: "Escaneo completado."})
			}
		}()
		return nil
	}
}

// --- Actualización de Viewports de Detalles ---

func (m *Model) updateAllDetails() {
	m.updateInterceptDetail()
	m.updateHistoryDetail()
}

func (m *Model) updateInterceptDetail() {
	if len(m.pendingTx) == 0 || m.selectedIndex < 0 || m.selectedIndex >= len(m.pendingTx) {
		m.interceptVp.SetContent("No hay peticiones interceptadas en cola...")
		return
	}
	tx := m.pendingTx[m.selectedIndex]
	m.interceptVp.SetContent(formatTransactionDetails(tx, 0))
}

func (m *Model) updateHistoryDetail() {
	if len(m.historyTx) == 0 || m.historyIdx < 0 || m.historyIdx >= len(m.historyTx) {
		m.historyVp.SetContent("Selecciona una petición de la lista para inspeccionarla...")
		return
	}
	tx := m.historyTx[m.historyIdx]

	// Carga bajo demanda de los cuerpos si no han sido inicializados
	if tx.RequestBody == nil && tx.ResponseBody == nil && m.historyManager != nil {
		reqB, respB, err := m.historyManager.GetBodies(context.Background(), tx.ID)
		if err == nil {
			if reqB == nil {
				tx.RequestBody = []byte{}
			} else {
				tx.RequestBody = reqB
			}
			if respB == nil {
				tx.ResponseBody = []byte{}
			} else {
				tx.ResponseBody = respB
			}
		}
	}

	m.historyVp.SetContent(formatTransactionDetails(tx, m.historySubTab))
}

func (m *Model) updateDecoderOutput() {
	input := m.decoderInput.Value()
	if input == "" {
		m.decoderVp.SetContent("Escribe algo en el panel superior para codificar/decodificar...")
		return
	}

	var sb strings.Builder
	sb.WriteString(highlight.Render("=== BASE64 ==="))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Encode: %s\n", base64.StdEncoding.EncodeToString([]byte(input))))
	if dec, err := base64.StdEncoding.DecodeString(input); err == nil {
		sb.WriteString(fmt.Sprintf("Decode: %s\n", string(dec)))
	} else {
		sb.WriteString("Decode: [Base64 Inválido]\n")
	}
	sb.WriteString("\n")

	sb.WriteString(highlight.Render("=== URL ENCODE ==="))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Encode: %s\n", url.QueryEscape(input)))
	if dec, err := url.QueryUnescape(input); err == nil {
		sb.WriteString(fmt.Sprintf("Decode: %s\n", dec))
	}
	sb.WriteString("\n")

	sb.WriteString(highlight.Render("=== HEXADECIMAL ==="))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Encode: %s\n", hex.EncodeToString([]byte(input))))
	if dec, err := hex.DecodeString(strings.ReplaceAll(input, " ", "")); err == nil {
		sb.WriteString(fmt.Sprintf("Decode: %s\n", string(dec)))
	} else {
		sb.WriteString("Decode: [Hex Inválido]\n")
	}
	sb.WriteString("\n")

	sb.WriteString(highlight.Render("=== HTML ENTITIES ==="))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Escape:   %s\n", html.EscapeString(input)))
	sb.WriteString(fmt.Sprintf("Unescape: %s\n", html.UnescapeString(input)))

	m.decoderVp.SetContent(sb.String())
}

// --- Layout y Renderizado ---

func (m *Model) resizeViewports() {
	if !m.ready {
		return
	}

	halfWidth := m.width / 2
	adjustedHeight := m.height - m.heightOffset
	if adjustedHeight < 15 {
		adjustedHeight = 15
	}

	// --- 1. Intercept ---
	m.interceptVp.Width = halfWidth - 6
	m.interceptVp.Height = adjustedHeight - 13
	m.interceptTa.SetWidth(halfWidth - 6)
	m.interceptTa.SetHeight(adjustedHeight - 13)

	// --- 2. History & Sitemap ---
	leftTotalHeight := adjustedHeight - 13
	topBoxHeight := leftTotalHeight / 2
	bottomBoxHeight := leftTotalHeight - topBoxHeight

	m.historyVp.Width = halfWidth - 6
	m.historyVp.Height = adjustedHeight - 15

	m.sitemapVp.Width = halfWidth - 6
	sitemapH := bottomBoxHeight - 4
	if sitemapH < 2 {
		sitemapH = 2
	}
	m.sitemapVp.Height = sitemapH

	// --- 3. Repeater ---
	for _, slot := range m.repeaterSlots {
		slot.RequestArea.SetWidth(halfWidth - 6)
		slot.RequestArea.SetHeight(adjustedHeight - 16)

		slot.ResponseView.Width = halfWidth - 6
		if slot.ResponseAudit != "" {
			h := adjustedHeight - 16 - 7
			if h < 5 {
				h = 5
			}
			slot.ResponseView.Height = h
		} else {
			slot.ResponseView.Height = adjustedHeight - 16
		}
	}

	// --- 4. Decoder ---
	m.decoderInput.SetWidth(m.width - 8)
	m.decoderInput.SetHeight(3)
	m.decoderVp.Width = m.width - 8
	m.decoderVp.Height = adjustedHeight - 22
}

func (m *Model) View() string {
	if !m.ready {
		return "Inicializando interfaz..."
	}
	if m.exitConfirm {
		return m.renderExitConfirmView()
	}

	var sb strings.Builder

	// 1. Título Banner
	bannerText := " SPYDEX v0.1.8 "
	if m.heightOffset > 0 {
		bannerText += fmt.Sprintf("(Calibración: -%d lín.) ", m.heightOffset)
	}
	sb.WriteString(titleStyle.Render(bannerText))
	sb.WriteString("  ")
	
	// Estado de interceptación (siempre visible en la barra superior)
	if m.coordinator.IsInterceptEnabled() {
		sb.WriteString(successStyle.Render("[INTERCEPT ON]"))
	} else {
		sb.WriteString(dangerStyle.Render("[INTERCEPT OFF]"))
	}
	sb.WriteString("\n")

	// 2. Barra de Pestañas
	tabs := []string{
		"1: Intercept",
		"2: History",
		"3: Repeater",
		"4: Decoder",
		"5: Automator",
	}
	var renderedTabs []string
	for i, t := range tabs {
		if i == m.activeTab {
			renderedTabs = append(renderedTabs, tabActiveStyle.Render(t))
		} else {
			renderedTabs = append(renderedTabs, tabInactiveStyle.Render(t))
		}
	}
	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...))
	sb.WriteString("\n\n")

	// 3. Contenido de la pestaña activa
	switch m.activeTab {
	case 0:
		sb.WriteString(m.renderInterceptView())
	case 1:
		sb.WriteString(m.renderHistoryView())
	case 2:
		sb.WriteString(m.renderRepeaterView())
	case 3:
		sb.WriteString(m.renderDecoderView())
	case 4:
		sb.WriteString(m.renderAutomatorView())
	}

	sb.WriteString("\n")

	// 4. Pie de página con atajos contextuados
	sb.WriteString(m.renderFooter())

	return sb.String()
}

func (m *Model) renderInterceptView() string {
	halfWidth := m.width / 2
	adjustedHeight := m.height - m.heightOffset
	if adjustedHeight < 15 {
		adjustedHeight = 15
	}

	// Panel izquierdo (lista de peticiones pendientes)
	var leftPanel strings.Builder
	leftPanel.WriteString(highlight.Render("Peticiones Pendientes"))
	leftPanel.WriteString("\n")

	listHeight := adjustedHeight - 15
	if listHeight < 5 {
		listHeight = 5
	}

	if len(m.pendingTx) == 0 {
		leftPanel.WriteString("\n  No hay peticiones interceptadas.\n  Activa 'Intercept ON' y envía tráfico.")
	} else {
		for i, tx := range m.pendingTx {
			if i >= listHeight {
				break
			}
			row := fmt.Sprintf(" %s %s %s%s", tx.Method, tx.Host, tx.Path, strings.Repeat(" ", 100))
			row = truncate(row, halfWidth-5)

			if i == m.selectedIndex {
				leftPanel.WriteString(selectedRowStyle.Render("> "+row))
				leftPanel.WriteString("\n")
			} else {
				leftPanel.WriteString(normalRowStyle.Render("  "+row))
				leftPanel.WriteString("\n")
			}
		}
	}

	leftStyle := unfocusedPanelStyle
	rightStyle := unfocusedPanelStyle
	if m.interceptFocus == 0 {
		leftStyle = focusedPanelStyle
	} else {
		if m.interceptEditing {
			rightStyle = focusedPanelStyle.BorderForeground(purpleColor)
		} else {
			rightStyle = focusedPanelStyle
		}
	}

	leftStr := renderStaticBox(leftStyle, halfWidth - 2, adjustedHeight - 11, leftPanel.String())
	
	var rightContent string
	if m.interceptEditing {
		rightContent = m.interceptTa.View()
	} else {
		rightContent = m.interceptVp.View()
	}
	rightStr := renderStaticBox(rightStyle, halfWidth - 2, adjustedHeight - 11, rightContent)

	return lipgloss.JoinHorizontal(lipgloss.Top, leftStr, " ", rightStr)
}

func (m *Model) renderHistoryView() string {
	halfWidth := m.width / 2
	adjustedHeight := m.height - m.heightOffset
	if adjustedHeight < 15 {
		adjustedHeight = 15
	}
	leftTotalHeight := adjustedHeight - 13
	topBoxHeight := leftTotalHeight / 2
	bottomBoxHeight := leftTotalHeight - topBoxHeight

	// Panel izquierdo superior (Lista de historial)
	var leftPanel strings.Builder
	leftPanel.WriteString(highlight.Render("Historial SQLite"))
	leftPanel.WriteString("\n")

	listHeight := topBoxHeight - 4
	if listHeight < 1 {
		listHeight = 1
	}

	if len(m.historyTx) == 0 {
		leftPanel.WriteString("\n  Historial vacío. Navega a páginas para registrar tráfico.")
	} else {
		start := 0
		if len(m.historyTx) > listHeight {
			start = m.historyIdx - (listHeight / 2)
			if start < 0 {
				start = 0
			}
			if start+listHeight > len(m.historyTx) {
				start = len(m.historyTx) - listHeight
			}
		}

		for i := start; i < start+listHeight && i < len(m.historyTx); i++ {
			tx := m.historyTx[i]
			status := "---"
			if tx.Response != nil {
				status = fmt.Sprintf("%d", tx.Response.StatusCode)
			}
			row := fmt.Sprintf("[%s] %s %s %s%s", status, tx.Method, tx.Host, tx.Path, strings.Repeat(" ", 100))
			row = truncate(row, halfWidth-5)

			if i == m.historyIdx {
				leftPanel.WriteString(selectedRowStyle.Render("> "+row))
				leftPanel.WriteString("\n")
			} else {
				leftPanel.WriteString(normalRowStyle.Render("  "+row))
				leftPanel.WriteString("\n")
			}
		}
	}

	// Panel izquierdo inferior (Sitemap del Target)
	var sitemapPanel strings.Builder
	sitemapPanel.WriteString(highlight.Render("Sitemap del Target"))
	sitemapPanel.WriteString("\n")
	sitemapPanel.WriteString(m.sitemapVp.View())

	// Selector de sub-pestañas para los detalles con indicador de foco
	var prefix string
	if m.historyFocus == 2 {
		prefix = highlight.Render("> ")
	} else {
		prefix = "  "
	}

	var renderedSubTabs string
	if m.historySubTab == 0 {
		renderedSubTabs = lipgloss.JoinHorizontal(lipgloss.Center,
			tabActiveStyle.Render(" REQUEST "),
			tabInactiveStyle.Render(" RESPONSE "),
		)
	} else {
		renderedSubTabs = lipgloss.JoinHorizontal(lipgloss.Center,
			tabInactiveStyle.Render(" REQUEST "),
			tabActiveStyle.Render(" RESPONSE "),
		)
	}
	subTabsStr := lipgloss.JoinHorizontal(lipgloss.Center, prefix, renderedSubTabs)

	// Focus border styling para los paneles exteriores principales
	topStyle := unfocusedPanelStyle
	sitemapStyle := unfocusedPanelStyle
	rightStyle := unfocusedPanelStyle

	if m.historyFocus == 0 {
		topStyle = focusedPanelStyle
	} else if m.historyFocus == 1 {
		sitemapStyle = focusedPanelStyle
	} else if m.historyFocus == 2 || m.historyFocus == 3 {
		rightStyle = focusedPanelStyle
	}

	topLeftStr := renderStaticBox(topStyle, halfWidth - 2, topBoxHeight, leftPanel.String())
	bottomLeftStr := renderStaticBox(sitemapStyle, halfWidth - 2, bottomBoxHeight, sitemapPanel.String())
	leftStr := lipgloss.JoinVertical(lipgloss.Left, topLeftStr, bottomLeftStr)

	// Combinar el selector de sub-pestañas y el viewport sin bordes internos duplicados
	var rightBox strings.Builder
	rightBox.WriteString(subTabsStr)
	rightBox.WriteString("\n")
	rightBox.WriteString(m.historyVp.View())

	rightFinalStr := renderStaticBox(rightStyle, halfWidth - 2, adjustedHeight - 11, rightBox.String())

	return lipgloss.JoinHorizontal(lipgloss.Top, leftStr, " ", rightFinalStr)
}

func (m *Model) renderRepeaterView() string {
	halfWidth := m.width / 2
	adjustedHeight := m.height - m.heightOffset
	if adjustedHeight < 15 {
		adjustedHeight = 15
	}
	slot := m.repeaterSlots[m.activeSlot]

	// Encabezado de slots de Repeater
	var headerSlots []string
	for i := 0; i < 3; i++ {
		text := fmt.Sprintf(" Slot %d ", i+1)
		if i == m.activeSlot {
			headerSlots = append(headerSlots, tabActiveStyle.Render(text))
		} else {
			headerSlots = append(headerSlots, tabInactiveStyle.Render(text))
		}
	}
	slotsBar := lipgloss.JoinHorizontal(lipgloss.Top, headerSlots...) + "\n\n"

	leftStyle := unfocusedPanelStyle
	rightStyle := unfocusedPanelStyle
	if slot.Focused == 0 {
		if m.repeaterEditing {
			leftStyle = focusedPanelStyle.BorderForeground(purpleColor)
		} else {
			leftStyle = focusedPanelStyle
		}
	} else {
		rightStyle = focusedPanelStyle
	}

	leftStr := renderStaticBox(leftStyle, halfWidth - 2, adjustedHeight - 14, slot.RequestArea.View())
	
	var rightStr string
	if slot.ResponseAudit != "" {
		auditBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(accentColor).
			Padding(0, 2).
			Width(halfWidth - 6).
			Render(slot.ResponseAudit)

		h := adjustedHeight - 14 - 7
		if h < 5 {
			h = 5
		}
		renderedResponse := renderStaticBox(rightStyle, halfWidth - 2, h, slot.ResponseView.View())
		rightStr = auditBox + "\n" + renderedResponse
	} else {
		rightStr = renderStaticBox(rightStyle, halfWidth - 2, adjustedHeight - 14, slot.ResponseView.View())
	}

	return slotsBar + lipgloss.JoinHorizontal(lipgloss.Top, leftStr, " ", rightStr)
}

func (m *Model) renderDecoderView() string {
	adjustedHeight := m.height - m.heightOffset
	if adjustedHeight < 15 {
		adjustedHeight = 15
	}
	var inputStyle = unfocusedPanelStyle
	if m.decoderEditing {
		inputStyle = focusedPanelStyle.BorderForeground(purpleColor)
	} else {
		inputStyle = focusedPanelStyle
	}

	var sb strings.Builder
	sb.WriteString(highlight.Render("INPUT TEXT:"))
	sb.WriteString("\n")
	sb.WriteString(renderStaticBox(inputStyle, m.width - 4, 3, m.decoderInput.View()))
	sb.WriteString("\n\n")
	sb.WriteString(highlight.Render("OUTPUT TRANSFORMATION:"))
	sb.WriteString("\n")

	outHeight := adjustedHeight - 20
	if outHeight < 3 {
		outHeight = 3
	}
	sb.WriteString(renderStaticBox(focusedPanelStyle, m.width - 4, outHeight, m.decoderVp.View()))
	return sb.String()
}

func (m *Model) renderAutomatorView() string {
	adjustedHeight := m.height - m.heightOffset
	if adjustedHeight < 15 {
		adjustedHeight = 15
	}
	var sb strings.Builder
	
	// Título de la pestaña
	_, _ = sb.WriteString(highlight.Render("SPYDEX AUTOMATOR - SECURITY SCANNER & INTRUDER"))
	_, _ = sb.WriteString("\n\n")

	halfWidth := m.width / 2

	// Configuración del target y del escaneo (Panel Izquierdo)
	var leftPanel strings.Builder
	_, _ = leftPanel.WriteString(lipgloss.NewStyle().Bold(true).Foreground(accentColor).Render("[X]Configuración de Ataque"))
	_, _ = leftPanel.WriteString("\n\n")

	if m.automatorRequest == "" {
		_, _ = leftPanel.WriteString("  [Ninguna petición cargada]\n\n")
		_, _ = leftPanel.WriteString("  Para escanear:\n")
		_, _ = leftPanel.WriteString("  1. Ve a Intercept (1) o History (2)\n")
		_, _ = leftPanel.WriteString("  2. Selecciona una petición\n")
		_, _ = leftPanel.WriteString("  3. Presiona 'a' para mandarla aquí\n")
	} else {
		// Mostrar detalles cortos de la petición cargada
		req, _, err := parseRawRequest(m.automatorRequest)
		if err == nil {
			_, _ = leftPanel.WriteString(fmt.Sprintf("  Objetivo: %s %s\n", req.Method, req.URL.Host))
			_, _ = leftPanel.WriteString(fmt.Sprintf("  Ruta:     %s\n\n", req.URL.Path))
		}

		_, _ = leftPanel.WriteString(lipgloss.NewStyle().Underline(true).Render("Tipo de Escaneo (Presiona 'p' para cambiar):"))
		_, _ = leftPanel.WriteString("\n")
		types := []string{"Active Vulnerability Scan", "Path Discovery (Fuzz Paths)"}
		for i, t := range types {
			if i == m.automatorScanType {
				_, _ = leftPanel.WriteString(fmt.Sprintf("  [x] %s\n", highlight.Render(t)))
			} else {
				_, _ = leftPanel.WriteString(fmt.Sprintf("  [ ] %s\n", t))
			}
		}
		_, _ = leftPanel.WriteString("\n")

		if m.automatorRunning {
			_, _ = leftPanel.WriteString(dangerStyle.Render("  Escaneo en curso... Presiona 's' para DETENER.\n"))
		} else {
			_, _ = leftPanel.WriteString(successStyle.Render("  Listo. Presiona 's' para INICIAR el escaneo.\n"))
		}
	}

	// Logs y barra de progreso (Panel Derecho)
	var rightPanel strings.Builder
	_, _ = rightPanel.WriteString(lipgloss.NewStyle().Bold(true).Foreground(accentColor).Render("[+] Progreso y Logs"))
	_, _ = rightPanel.WriteString("\n\n")

	// Renderizar barra de progreso
	progWidth := halfWidth - 10
	if progWidth < 10 {
		progWidth = 10
	}
	filled := int(m.automatorProgress * float64(progWidth))
	if filled > progWidth {
		filled = progWidth
	}
	if filled < 0 {
		filled = 0
	}
	empty := progWidth - filled
	bar := fmt.Sprintf("[%s%s] %.0f%%", strings.Repeat("#", filled), strings.Repeat("-", empty), m.automatorProgress*100)
	_, _ = rightPanel.WriteString(bar + "\n\n")

	// Mostrar logs recientes
	_, _ = rightPanel.WriteString("Logs:\n")
	logHeight := adjustedHeight - 23
	if logHeight < 3 {
		logHeight = 3
	}
	startLog := len(m.automatorLog) - logHeight
	if startLog < 0 {
		startLog = 0
	}
	for i := startLog; i < len(m.automatorLog); i++ {
		_, _ = rightPanel.WriteString(fmt.Sprintf("  %s\n", m.automatorLog[i]))
	}

	leftStyle := unfocusedPanelStyle
	rightStyle := unfocusedPanelStyle

	// Unir paneles superiores horizontalmente
	upperLeft := renderStaticBox(leftStyle, halfWidth - 2, 10, leftPanel.String())
	upperRight := renderStaticBox(rightStyle, halfWidth - 2, 10, rightPanel.String())
	_, _ = sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, upperLeft, " ", upperRight))
	_, _ = sb.WriteString("\n\n")

	// Tabla de Hallazgos (Panel Inferior)
	_, _ = sb.WriteString(highlight.Render("[+] Hallazgos de Vulnerabilidades encontradas:"))
	_, _ = sb.WriteString("\n")

	var tableContent strings.Builder
	tableHeight := adjustedHeight - 29
	if tableHeight < 8 {
		tableHeight = 8
	}
	limit := tableHeight - 4

	// Encabezado de la tabla
	_, _ = tableContent.WriteString(fmt.Sprintf("  %-5s %-10s %-12s %-25s %s\n", "ID", "RIESGO", "MÉTODO", "VULNERABILIDAD", "PAYLOAD"))
	_, _ = tableContent.WriteString(strings.Repeat("-", m.width-8) + "\n")

	if len(m.automatorResults) == 0 {
		_, _ = tableContent.WriteString("\n  No se han detectado hallazgos aún en este escaneo.")
	} else {
		for i, res := range m.automatorResults {
			if i >= limit {
				break
			}
			sevBadge := ""
			switch res.Severity {
			case "High":
				sevBadge = severityHighStyle.Render(" HIGH ")
			case "Medium":
				sevBadge = severityMediumStyle.Render(" MED  ")
			case "Low":
				sevBadge = severityLowStyle.Render(" LOW  ")
			default:
				sevBadge = severityInfoStyle.Render(" INFO ")
			}

			// Acortar URL/Issue si es muy larga
			issueTrunc := truncate(res.Issue, 23)
			payloadTrunc := truncate(res.Payload, 40)

			_, _ = tableContent.WriteString(fmt.Sprintf("  %-5d %-18s %-6s %-25s %s\n", 
				res.ID, sevBadge, res.Method, issueTrunc, payloadTrunc))
		}
	}

	_, _ = sb.WriteString(renderStaticBox(focusedPanelStyle, m.width - 4, tableHeight, tableContent.String()))
	return sb.String()
}

func (m *Model) renderFooter() string {
	switch m.activeTab {
	case 0:
		if m.interceptEditing {
			return footerStyle.Render("Insert Mode (Edición) | Ctrl+F: Enviar (Forward) | Ctrl+S: Guardar local | Esc: Modo Comando")
		}
		return footerStyle.Render("Tab: Foco | Flechas/k/j: Mover | e/Enter: Editar | f: Forward | d: Drop | r: Mandar a Repeater | y: Mandar a Decoder | a: Mandar a Automator | i: Intercept ON/OFF | Ctrl+C: Salir")
	case 1:
		return footerStyle.Render("Tab: Foco | Flechas/k/j: Lista | H/L o Flechas (izq/der) en Selector: Req/Resp | r: Mandar a Repeater | y: Mandar a Decoder | a: Mandar a Automator | i: Intercept ON/OFF | Ctrl+C: Salir")
	case 2:
		if m.repeaterEditing {
			return footerStyle.Render("Insert Mode (Edición) | Escribe cabeceras o cuerpo | Ctrl+S: Enviar Petición | Esc: Modo Comando")
		}
		slot := m.repeaterSlots[m.activeSlot]
		if slot.Focused == 0 {
			return footerStyle.Render("Tab: Foco | [ o ]: Cambiar Slot | e/Enter: Editar (Inserción) | Ctrl+S: Enviar | y: Mandar a Decoder | i: Intercept ON/OFF | Ctrl+C: Salir")
		}
		return footerStyle.Render("Tab: Foco | [ o ]: Cambiar Slot | Flechas/k/j: Scroll | y: Mandar a Decoder | i: Intercept ON/OFF | Ctrl+C: Salir")
	case 3:
		if m.decoderEditing {
			return footerStyle.Render("Insert Mode (Edición) | Escribe texto para transformar en tiempo real | Esc: Modo Comando")
		}
		return footerStyle.Render("e/Enter: Editar Texto (Inserción) | i: Intercept ON/OFF | 1-5: Pestañas | Ctrl+C: Salir")
	case 4:
		return footerStyle.Render("s: Iniciar/Detener Escaneo | p: Cambiar Tipo Escaneo | c: Limpiar | i: Intercept ON/OFF | 1-5: Pestañas | Ctrl+C: Salir")
	}
	return ""
}

// --- Auxiliares ---

func truncate(s string, l int) string {
	if len(s) <= l {
		return s
	}
	if l > 3 {
		return s[:l-3] + "..."
	}
	return s[:l]
}

func truncateColorLine(s string, limit int) string {
	var sb strings.Builder
	printableCount := 0
	inEscape := false

	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			sb.WriteRune(r)
			continue
		}
		if inEscape {
			sb.WriteRune(r)
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}

		if printableCount < limit {
			sb.WriteRune(r)
			printableCount++
		} else {
			sb.WriteString("\x1b[0m")
			break
		}
	}
	return sb.String()
}

func renderStaticBox(style lipgloss.Style, width, height int, content string) string {
	innerWidth := width - 4
	if innerWidth < 1 {
		innerWidth = 1
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		lines[i] = truncateColorLine(line, innerWidth)
	}

	if len(lines) > height {
		lines = lines[:height]
	} else {
		for len(lines) < height {
			lines = append(lines, "")
		}
	}
	return style.Width(width).Height(height).Render(strings.Join(lines, "\n"))
}

func formatTransactionDetails(tx *coordinator.Transaction, showResponse int) string {
	var sb strings.Builder

	if showResponse == 0 {
		// Request
		sb.WriteString(fmt.Sprintf("%s %s %s\n", tx.Method, tx.Request.URL, tx.Version))
		sb.WriteString(fmt.Sprintf("Host: %s\n", tx.Host))
		sb.WriteString(fmt.Sprintf("Hora: %s\n\n", tx.Timestamp.Format("15:04:05.000")))

		// Parse and list query parameters if present
		queryParams := tx.Request.URL.Query()
		if len(queryParams) > 0 {
			sb.WriteString(highlight.Render("--- Query Parameters ---"))
			sb.WriteString("\n")
			for k, v := range queryParams {
				sb.WriteString(fmt.Sprintf("  %s = %s\n", k, strings.Join(v, ", ")))
			}
			sb.WriteString("\n")
		}

		sb.WriteString(highlight.Render("--- Headers ---"))
		sb.WriteString("\n")
		for k, v := range tx.Request.Header {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", k, strings.Join(v, ", ")))
		}
		sb.WriteString("\n")

		sb.WriteString(highlight.Render("--- Body ---"))
		sb.WriteString("\n")
		if len(tx.RequestBody) > 0 {
			isJSON := false
			for _, ct := range tx.Request.Header["Content-Type"] {
				if strings.Contains(strings.ToLower(ct), "json") {
					isJSON = true
					break
				}
			}
			if isJSON {
				var pretty bytes.Buffer
				if err := json.Indent(&pretty, tx.RequestBody, "", "  "); err == nil {
					sb.Write(pretty.Bytes())
				} else {
					sb.Write(tx.RequestBody)
				}
			} else {
				sb.Write(tx.RequestBody)
			}
		} else {
			sb.WriteString("[Cuerpo de Request Vacío]")
		}
	} else {
		// Response
		if tx.Response == nil {
			sb.WriteString("Aún no hay respuesta del servidor para esta petición (petición pendiente o cancelada).")
		} else {
			statusText := fmt.Sprintf("HTTP/1.1 %d %s", tx.Response.StatusCode, http.StatusText(tx.Response.StatusCode))
			if tx.Response.StatusCode >= 200 && tx.Response.StatusCode < 300 {
				sb.WriteString(successStyle.Render(statusText))
			} else if tx.Response.StatusCode >= 300 && tx.Response.StatusCode < 400 {
				sb.WriteString(lipgloss.NewStyle().Foreground(orangeColor).Bold(true).Render(statusText))
			} else {
				sb.WriteString(dangerStyle.Render(statusText))
			}
			sb.WriteString("\n")
			sb.WriteString(fmt.Sprintf("Duración: %v\n\n", tx.Duration))

			sb.WriteString(highlight.Render("--- Headers ---"))
			sb.WriteString("\n")
			for k, v := range tx.Response.Header {
				sb.WriteString(fmt.Sprintf("  %s: %s\n", k, strings.Join(v, ", ")))
			}
			sb.WriteString("\n")

			sb.WriteString(highlight.Render("--- Body ---"))
			sb.WriteString("\n")
			if len(tx.ResponseBody) > 0 {
				isJSON := false
				for _, ct := range tx.Response.Header["Content-Type"] {
					if strings.Contains(strings.ToLower(ct), "json") {
						isJSON = true
						break
					}
				}
				if isJSON {
					var pretty bytes.Buffer
					if err := json.Indent(&pretty, tx.ResponseBody, "", "  "); err == nil {
						sb.Write(pretty.Bytes())
					} else {
						sb.Write(tx.ResponseBody)
					}
				} else {
					sb.Write(tx.ResponseBody)
				}
			} else {
				sb.WriteString("[Cuerpo de Respuesta Vacío]")
			}
		}
	}

	return sb.String()
}

func formatRawRequest(tx *coordinator.Transaction) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", tx.Method, tx.Path))
	sb.WriteString(fmt.Sprintf("Host: %s\n", tx.Host))
	for k, v := range tx.Request.Header {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	sb.WriteString("\n")
	if len(tx.RequestBody) > 0 {
		sb.Write(tx.RequestBody)
	}
	return sb.String()
}

func sendRepeaterRequest(raw string) (string, string, error) {
	req, _, err := parseRawRequest(raw)
	if err != nil {
		return "", "", fmt.Errorf("error de parseo: %w", err)
	}

	// Quitar RequestURI ya que http.Client.Do fallará si está presente
	req.RequestURI = ""

	// Crear cliente con timeout e InsecureSkipVerify para permitir pruebas con certificados auto-firmados
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: tr,
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("error de red: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	duration := time.Since(start)
	if err != nil {
		return "", "", fmt.Errorf("leyendo body de respuesta: %w", err)
	}

	// Construir recuadro con detalles clave para la auditoría
	statusText := fmt.Sprintf("STATUS: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	timeText := fmt.Sprintf("RESPONSE TIME: %v", duration.Round(time.Millisecond))
	sizeText := fmt.Sprintf("BODY SIZE: %.2f KB (%d bytes)", float64(len(body))/1024.0, len(body))
	protoText := fmt.Sprintf("PROTOCOL: %s", resp.Proto)

	boxContent := fmt.Sprintf("[ REPEATER AUDIT DETAILS ]\n  * %s\n  * %s\n  * %s\n  * %s", 
		statusText, timeText, sizeText, protoText)

	var sb strings.Builder
	_, _ = sb.WriteString(fmt.Sprintf("%s %s\n", resp.Proto, resp.Status))
	for k, v := range resp.Header {
		_, _ = sb.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	_, _ = sb.WriteString("\n")

	// Formatear JSON si corresponde
	isJSON := false
	for _, ct := range resp.Header["Content-Type"] {
		if strings.Contains(strings.ToLower(ct), "json") {
			isJSON = true
			break
		}
	}
	if isJSON {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, body, "", "  "); err == nil {
			sb.Write(pretty.Bytes())
		} else {
			sb.Write(body)
		}
	} else {
		sb.Write(body)
	}

	return sb.String(), boxContent, nil
}

func doRepeaterRequest(slot int, raw string) tea.Cmd {
	return func() tea.Msg {
		res, audit, err := sendRepeaterRequest(raw)
		return repeaterResultMsg{slot: slot, text: res, audit: audit, err: err}
	}
}

// --- Sitemap Helpers ---

type sitemapRow struct {
	text string
	path string
}

type sitemapNode struct {
	name     string
	children map[string]*sitemapNode
}

func newSitemapNode(name string) *sitemapNode {
	return &sitemapNode{
		name:     name,
		children: make(map[string]*sitemapNode),
	}
}

func (n *sitemapNode) addPath(segments []string) {
	if len(segments) == 0 {
		return
	}
	first := segments[0]
	if first == "" {
		if len(segments) > 1 {
			n.addPath(segments[1:])
		}
		return
	}
	child, exists := n.children[first]
	if !exists {
		child = newSitemapNode(first)
		n.children[first] = child
	}
	child.addPath(segments[1:])
}

func (n *sitemapNode) buildRows(currentPath string, indent string, isLast bool, rows *[]sitemapRow) {
	newPath := currentPath
	if n.name != "" {
		newPath = currentPath + "/" + n.name
		connector := "└── "
		if !isLast {
			connector = "├── "
		}
		*rows = append(*rows, sitemapRow{
			text: indent + connector + n.name,
			path: newPath,
		})
	}

	var keys []string
	for k := range n.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	nextIndent := indent
	if n.name != "" {
		if isLast {
			nextIndent += "    "
		} else {
			nextIndent += "│   "
		}
	}

	for i, k := range keys {
		childIsLast := (i == len(keys)-1)
		n.children[k].buildRows(newPath, nextIndent, childIsLast, rows)
	}
}

func (m *Model) getSitemapRows() (string, []sitemapRow) {
	hostsMap := make(map[string]bool)
	for _, tx := range m.historyTx {
		if tx.Host != "" {
			hostsMap[tx.Host] = true
		}
	}
	var hosts []string
	for k := range hostsMap {
		hosts = append(hosts, k)
	}
	sort.Strings(hosts)

	if len(hosts) == 0 {
		return "", nil
	}

	if m.sitemapDomainIdx < 0 {
		m.sitemapDomainIdx = 0
	}
	if m.sitemapDomainIdx >= len(hosts) {
		m.sitemapDomainIdx = len(hosts) - 1
	}

	selectedHost := hosts[m.sitemapDomainIdx]

	root := newSitemapNode("")
	for _, tx := range m.historyTx {
		if tx.Host == selectedHost {
			p := tx.Path
			if p == "" {
				p = "/"
			}
			parts := strings.Split(p, "/")
			root.addPath(parts)
		}
	}

	var rows []sitemapRow
	root.buildRows("", "", true, &rows)
	return selectedHost, rows
}

func (m *Model) updateSitemapContent() {
	hostsMap := make(map[string]bool)
	for _, tx := range m.historyTx {
		if tx.Host != "" {
			hostsMap[tx.Host] = true
		}
	}
	var hosts []string
	for k := range hostsMap {
		hosts = append(hosts, k)
	}
	sort.Strings(hosts)

	if len(hosts) == 0 {
		m.sitemapVp.SetContent("\n  Sitemap vacío. Esperando tráfico...")
		return
	}

	_, rows := m.getSitemapRows()

	// Asegurar que el índice de fila sea válido
	if m.sitemapRowIdx < 0 {
		m.sitemapRowIdx = 0
	}
	if len(rows) > 0 && m.sitemapRowIdx >= len(rows) {
		m.sitemapRowIdx = len(rows) - 1
	}

	var sb strings.Builder

	// Encabezado de hosts
	sb.WriteString("DOMINIOS: ")
	for i, h := range hosts {
		if i == m.sitemapDomainIdx {
			sb.WriteString(highlight.Render(fmt.Sprintf("[%s]", h)))
		} else {
			sb.WriteString(fmt.Sprintf(" %s ", h))
		}
		if i < len(hosts)-1 {
			sb.WriteString(" | ")
		}
	}
	sb.WriteString("\n\n")

	// Árbol jerárquico
	if len(rows) == 0 {
		sb.WriteString("  [Árbol vacío]")
	} else {
		for idx, row := range rows {
			if idx == m.sitemapRowIdx && m.historyFocus == 1 {
				sb.WriteString(selectedRowStyle.Render("> " + row.text))
				sb.WriteString("\n")
			} else if idx == m.sitemapRowIdx {
				sb.WriteString("> ")
				sb.WriteString(row.text)
				sb.WriteString("\n")
			} else {
				sb.WriteString("  ")
				sb.WriteString(row.text)
				sb.WriteString("\n")
			}
		}
	}

	m.sitemapVp.SetContent(sb.String())
}

func findMatchingTxIndex(txs []*coordinator.Transaction, host string, path string) int {
	// 1. Intentar coincidencia exacta
	for i, tx := range txs {
		if tx.Host == host && tx.Path == path {
			return i
		}
	}
	// 2. Intentar coincidencia prefijo (ej: si seleccionó un directorio)
	for i, tx := range txs {
		if tx.Host == host && strings.HasPrefix(tx.Path, path+"/") {
			return i
		}
	}
	return -1
}

func (m *Model) renderExitConfirmView() string {
	boxWidth := 60

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(accentColor).Bold(true).Render("  SPYDEX v0.1.8 - CONFIRMACIÓN DE SALIDA"))
	sb.WriteString("\n\n")
	sb.WriteString("  ¿Deseas conservar la persistencia de la base de datos?\n")
	sb.WriteString("  (Esto mantendrá el historial guardado en SQLite para la próxima sesión)\n\n\n")
	sb.WriteString("    ")
	sb.WriteString(lipgloss.NewStyle().Foreground(greenColor).Bold(true).Render("[Y]"))
	sb.WriteString(" Sí, guardar y salir\n")

	sb.WriteString("    ")
	sb.WriteString(lipgloss.NewStyle().Foreground(redColor).Bold(true).Render("[N]"))
	sb.WriteString(" No, borrar base de datos y salir\n")

	sb.WriteString("    ")
	sb.WriteString(lipgloss.NewStyle().Foreground(grayColor).Bold(true).Render("[Cualquier otra tecla]"))
	sb.WriteString(" Cancelar y volver\n\n")

	dialog := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(accentColor).
		Padding(1, 2).
		Width(boxWidth)

	// Centrar vertical y horizontalmente en pantalla
	totalContent := dialog.Render(sb.String())
	renderedWidth := lipgloss.Width(totalContent)
	renderedHeight := lipgloss.Height(totalContent)
	
	// Rellenar saltos de línea arriba para centrar verticalmente
	vPadding := (m.height - renderedHeight) / 2
	if vPadding < 0 {
		vPadding = 0
	}
	hPadding := (m.width - renderedWidth) / 2
	if hPadding < 0 {
		hPadding = 0
	}

	leftIndent := strings.Repeat(" ", hPadding)
	lines := strings.Split(totalContent, "\n")
	var centeredLines []string
	for _, l := range lines {
		centeredLines = append(centeredLines, leftIndent+l)
	}

	return strings.Repeat("\n", vPadding) + strings.Join(centeredLines, "\n")
}