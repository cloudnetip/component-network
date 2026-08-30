package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptrace"
	"netip-network/libs/logger"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	defaultEndpoint = "https://cloudnetip.com/api"

	writeWait = 8 * time.Second

	defaultPongWait   = 90 * time.Second
	defaultPingPeriod = 30 * time.Second

	apiTimeout     = 15 * time.Second
	wsDialTimeout  = 15 * time.Second
	tcpDialTimeout = 12 * time.Second

	maxMessageSize = 1 << 20

	backoffMin            = 1 * time.Second
	backoffMax            = 10 * time.Second
	slotsExhaustedWait    = 5 * time.Minute
	defaultReconnectDelay = 1 * time.Second
	minStableSession      = 60 * time.Second
	closeGrace            = 2 * time.Second
	dropLogInterval       = 10 * time.Second
)

var (
	errSlotsExhausted   = errors.New("number of nodes has been reached")
	errConnectionClosed = errors.New("connection closed")
)

type ResponseBase struct {
	Ok           bool   `json:"ok"`
	Code         string `json:"code"`
	Message      string `json:"message"`
	EndpointIP   string `json:"endpointIP"`
	EndpointPath string `json:"endpointPath"`
	HandshakeKey string `json:"handshakeKey"`
}

type PayloadBase struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
}

type apiError struct {
	code    string
	message string
}

func (e *apiError) Error() string {
	if e.code != "" {
		return "api message: " + e.message + " (code: " + e.code + ")"
	}
	return "api message: " + e.message
}

func (e *apiError) Is(target error) bool {
	if target != errSlotsExhausted {
		return false
	}
	return e.code == "nodes_limit_reached" ||
		strings.Contains(e.message, "number of nodes has been reached")
}

type session struct {
	ws        *websocket.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	startedAt time.Time

	once sync.Once
	err  error
}

func newSession(parent context.Context, ws *websocket.Conn) *session {
	ctx, cancel := context.WithCancel(parent)
	return &session{ws: ws, ctx: ctx, cancel: cancel, startedAt: time.Now()}
}

func (s *session) close(reason error) {
	s.once.Do(func() {
		s.err = reason
		s.cancel()
		_ = s.ws.Close()
	})
}

func (s *session) reason() error {
	if s.err != nil {
		return s.err
	}
	return errors.New("peer closed connection")
}

type Connection struct {
	client   *http.Client
	payload  *ConnectPayload
	endpoint string

	pongWait       time.Duration
	pingPeriod     time.Duration
	reconnectDelay time.Duration

	cur      atomic.Pointer[session]
	response atomic.Pointer[ConnectResponse]

	chanSend chan any
	chanLive chan []byte

	ctx    context.Context
	cancel context.CancelFunc

	done      chan struct{}
	closeOnce sync.Once

	dropped     atomic.Uint64
	lastDropLog atomic.Int64
}

func newConnection(cp *ConnectPayload) *Connection {
	ctx, cancel := context.WithCancel(context.Background())

	endpoint := strings.TrimRight(os.Getenv("ENDPOINT"), "/")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	pong := envDuration("WS_PONG_WAIT", defaultPongWait)

	return &Connection{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   6 * time.Second,
					KeepAlive: 15 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				MaxConnsPerHost:       20,
				IdleConnTimeout:       60 * time.Second,
			},
		},
		payload:        cp,
		endpoint:       endpoint,
		pongWait:       pong,
		pingPeriod:     sanePingPeriod(envDuration("WS_PING_PERIOD", defaultPingPeriod), pong),
		reconnectDelay: envDuration("WS_RECONNECT_DELAY", defaultReconnectDelay),
		chanSend:       make(chan any, 16),
		chanLive:       make(chan []byte, 16),
		ctx:            ctx,
		cancel:         cancel,
		done:           make(chan struct{}),
	}
}

func NewConnection(cp *ConnectPayload) *Connection {
	c := newConnection(cp)
	log.Println("[connect] started")
	c.connectWithRetry()
	go c.maintain()
	return c
}

func (c *Connection) Response() *ConnectResponse {
	return c.response.Load()
}

func (c *Connection) Live() <-chan []byte {
	return c.chanLive
}

func (c *Connection) Send(v any) bool {
	select {
	case <-c.done:
		return false
	default:
	}

	select {
	case c.chanSend <- v:
		return true
	default:
		n := c.dropped.Add(1)
		if c.allowDropLog() {
			log.Printf("[connect] notice: send chan is throttling, messages dropped: %d", n)
		}
		return false
	}
}

func (c *Connection) allowDropLog() bool {
	now := time.Now().UnixNano()
	last := c.lastDropLog.Load()
	if now-last < int64(dropLogInterval) {
		return false
	}
	return c.lastDropLog.CompareAndSwap(last, now)
}

func (c *Connection) maintain() {
	log.Println("[connect] maintenance")

	backoff := c.reconnectDelay

	for {
		s := c.cur.Load()
		if s == nil {
			return
		}

		select {
		case <-s.ctx.Done():
		case <-c.done:
			return
		}
		if c.stopping() {
			return
		}

		lived := time.Since(s.startedAt)
		if lived >= minStableSession {
			// reset backoff
			backoff = c.reconnectDelay
		}

		log.Printf("[connect] connection lost after %s, err: %s",
			lived.Round(time.Millisecond), s.reason())

		d := jitter(backoff)
		log.Printf("[connect] reconnect in %s", d.Round(time.Millisecond))
		if !c.sleep(d) {
			return
		}
		backoff = min(backoff*2, backoffMax)

		if !c.connectWithRetry() {
			return
		}
		log.Println("[connect] reconnected")
	}
}

func (c *Connection) connectWithRetry() bool {
	backoff := backoffMin
	for {
		if c.stopping() {
			return false
		}

		err := c.connect(c.ctx)
		if err == nil {
			return true
		}

		wait := backoff
		if errors.Is(err, errSlotsExhausted) {
			wait = slotsExhaustedWait
		} else {
			backoff = min(backoff*2, backoffMax)
		}

		wait = jitter(wait)
		log.Printf("[connect] failure: %s; retry in %s", err, wait.Round(time.Millisecond))
		if !c.sleep(wait) {
			return false
		}
	}
}

func (c *Connection) connect(ctx context.Context) error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("hostname: %w", err)
	}
	c.payload.Hostname = hostname

	plJs, err := json.Marshal(c.payload)
	if err != nil {
		c.fatal(fmt.Errorf("marshal payload: %w", err))
	}

	res, err := c.handshakeAPI(ctx, plJs)
	if err != nil {
		return err
	}
	c.response.Store(res)

	logger.Debugf("[connect] try connect to ws... endpoint ip: %q endpoint path: %q",
		res.EndpointIP, res.EndpointPath)

	ws, err := c.dialWS(ctx, res)
	if err != nil {
		return err
	}

	if err = c.handshakeWS(ws, res); err != nil {
		_ = ws.Close()
		return err
	}

	s := newSession(c.ctx, ws)
	c.cur.Store(s)
	go c.reader(s)
	go c.writer(s)

	return nil
}

func (c *Connection) handshakeAPI(ctx context.Context, body []byte) (*ConnectResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.endpoint+"/nodes/handshake/v2", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Key", os.Getenv("CONNECT_KEY"))
	req.Header.Set("X-Version", os.Getenv("VERSION"))
	req.Header.Set("X-Version-Hash", os.Getenv("VERSION_HASH"))

	if logger.IsDebugMode() {
		logger.Debugf("[connect] try connect to api... payload: %+v x-version: %q x-version-hash: %q",
			c.payload, os.Getenv("VERSION"), os.Getenv("VERSION_HASH"))
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), newDebugTrace()))
	}

	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("handshake request: %w", err)
	}
	defer func() {
		// for save keep-alive reusing
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxMessageSize))
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(res.Body, 256))
		return nil, fmt.Errorf("handshake status %s: %s",
			res.Status, strings.TrimSpace(string(snippet)))
	}

	cr := new(ConnectResponse)
	if err = json.NewDecoder(io.LimitReader(res.Body, maxMessageSize)).Decode(cr); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	if !cr.Ok {
		return nil, &apiError{code: cr.Code, message: cr.Message}
	}
	if cr.EndpointPath == "" {
		return nil, errors.New("api returned empty endpoint path")
	}

	return cr, nil
}

func (c *Connection) dialWS(ctx context.Context, r *ConnectResponse) (*websocket.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, wsDialTimeout)
	defer cancel()

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: wsDialTimeout,
	}

	// connect with replace ip
	if ip := r.EndpointIP; ip != "" {
		dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				log.Println("[connect] parse addr dial, err:", err)
			} else {
				addr = net.JoinHostPort(ip, port)
			}
			netDialer := &net.Dialer{
				Timeout:   tcpDialTimeout,
				KeepAlive: 15 * time.Second,
			}
			return netDialer.DialContext(ctx, network, addr)
		}
	}

	ws, res, err := dialer.DialContext(ctx, r.EndpointPath, nil)
	if err != nil {
		if res != nil && res.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
			_ = res.Body.Close()
		}
		if r.EndpointIP != "" {
			return nil, fmt.Errorf("dial modified: %w", err)
		}
		return nil, fmt.Errorf("dial native: %w", err)
	}

	ws.SetReadLimit(maxMessageSize)
	return ws, nil
}

func (c *Connection) handshakeWS(ws *websocket.Conn, r *ConnectResponse) error {
	logger.Debugf("[connect] send handshake...")

	_ = ws.SetWriteDeadline(time.Now().Add(writeWait))
	err := ws.WriteJSON(struct {
		Event   string `json:"event"`
		Key     string `json:"key"`
		Service string `json:"service"`
	}{
		"handshake",
		r.HandshakeKey,
		c.payload.Service,
	})
	if err != nil {
		return fmt.Errorf("handshake: write: %w", err)
	}

	logger.Debugf("[connect] read handshake...")

	_ = ws.SetReadDeadline(time.Now().Add(c.pongWait))
	_, p, err := ws.ReadMessage()
	if err != nil {
		return fmt.Errorf("handshake: read: %w", err)
	}

	logger.Debugf("[connect] handshake ack: %s", p)

	var ack struct {
		Ok      *bool  `json:"ok"`
		Message string `json:"message"`
	}
	if err = json.Unmarshal(p, &ack); err == nil && ack.Ok != nil && !*ack.Ok {
		return fmt.Errorf("handshake rejected: %s", ack.Message)
	}

	log.Println("[connect] handshake successful")
	return nil
}

func (c *Connection) reader(s *session) {
	defer s.close(nil)

	s.ws.SetPongHandler(func(string) error {
		return s.ws.SetReadDeadline(time.Now().Add(c.pongWait))
	})
	_ = s.ws.SetReadDeadline(time.Now().Add(c.pongWait))

	for {
		messageType, r, err := s.ws.NextReader()
		if err != nil {
			s.close(fmt.Errorf("read pump: %w", err))
			return
		}
		p, err := io.ReadAll(io.LimitReader(r, maxMessageSize))
		if err != nil {
			s.close(fmt.Errorf("read pump: msg type: %d: %w", messageType, err))
			return
		}
		select {
		case c.chanLive <- p:
		default:
			if c.allowDropLog() {
				log.Println("[connect] notice: live chan is throttling")
			}
		}
	}
}

func (c *Connection) writer(s *session) {
	defer s.close(nil)

	ticker := time.NewTicker(c.pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return

		case <-c.done:
			_ = s.ws.SetWriteDeadline(time.Now().Add(writeWait))
			err := s.ws.WriteMessage(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("[connect] write pump close err:", err)
			}
			return

		case message, ok := <-c.chanSend:
			if !ok {
				s.close(errors.New("write pump: hub closed the channel"))
				return
			}
			_ = s.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := s.ws.WriteJSON(message); err != nil {
				s.close(fmt.Errorf("write pump: %w", err))
				return
			}

		case <-ticker.C:
			logger.Debug("[connect] write pump: send ping")
			_ = s.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := s.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				s.close(fmt.Errorf("write pump: ticker write ping: %w", err))
				return
			}
		}
	}
}

func (c *Connection) close() {
	c.closeOnce.Do(func() {
		close(c.done)

		if s := c.cur.Load(); s != nil {
			select {
			case <-s.ctx.Done():
			case <-time.After(closeGrace):
			}
		}

		c.cancel()
		if s := c.cur.Load(); s != nil {
			s.close(errConnectionClosed)
		}
	})
}

func (c *Connection) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-c.done:
		return false
	case <-c.ctx.Done():
		return false
	}
}

func (c *Connection) stopping() bool {
	select {
	case <-c.done:
		return true
	default:
	}
	return c.ctx.Err() != nil
}

func (c *Connection) fatal(err error) {
	log.Println("[connect] fatal: shutting down in 5 seconds, err:", err)
	time.Sleep(5 * time.Second)
	os.Exit(1)
}

// jitter reconnect throttling
func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("[connect] invalid %s=%q, using %s", key, v, def)
		return def
	}
	return d
}

func sanePingPeriod(ping, pong time.Duration) time.Duration {
	if ping >= pong {
		return pong * 9 / 10
	}
	return ping
}

func newDebugTrace() *httptrace.ClientTrace {
	start := time.Now()
	return &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			logger.Debug("[connect] http trace: dns start", time.Since(start))
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			logger.Debug("[connect] http trace: dns done", time.Since(start), "addrs:", info.Addrs)
		},
		ConnectStart: func(network, addr string) {
			logger.Debug("[connect] http trace: connect start", network, addr, time.Since(start))
		},
		ConnectDone: func(network, addr string, err error) {
			logger.Debug("[connect] http trace: connect done", network, addr, "err:", err, time.Since(start))
		},
		TLSHandshakeStart: func() {
			logger.Debug("[connect] http trace: tls handshake start", time.Since(start))
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			logger.Debug("[connect] http trace: tls handshake done err:", err, time.Since(start))
		},
		GotConn: func(info httptrace.GotConnInfo) {
			logger.Debug("[connect] http trace: got connect reused:", info.Reused, time.Since(start))
		},
	}
}
