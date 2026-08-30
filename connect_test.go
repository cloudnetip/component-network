package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const testHandshakeKey = "test-handshake-key"

type wsServer struct {
	http     *httptest.Server
	upgrader websocket.Upgrader

	mu            sync.Mutex
	accepted      int
	open          int
	apiHits       int
	apiStatus     int
	apiBody       string
	rejectWS      bool
	muteUpTo      int
	lastHandshake handshakeFrame
	received      []string
}

type handshakeFrame struct {
	Event   string `json:"event"`
	Key     string `json:"key"`
	Service string `json:"service"`
}

func newWSServer(t *testing.T) *wsServer {
	t.Helper()

	s := &wsServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/nodes/handshake/v2", s.handleAPI)
	mux.HandleFunc("/ws", s.handleWS)
	s.http = httptest.NewServer(mux)
	t.Cleanup(s.http.Close)

	return s
}

func (s *wsServer) handleAPI(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.apiHits++
	status, body := s.apiStatus, s.apiBody
	s.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ResponseBase{
		Ok:           true,
		EndpointPath: "ws://" + r.Host + "/ws",
		HandshakeKey: testHandshakeKey,
	})
}

func (s *wsServer) handleWS(w http.ResponseWriter, r *http.Request) {
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	s.mu.Lock()
	s.accepted++
	s.open++
	id := s.accepted
	reject := s.rejectWS
	s.mu.Unlock()

	defer func() {
		_ = ws.Close()
		s.mu.Lock()
		s.open--
		s.mu.Unlock()
	}()

	// answer pong only connect not mute
	ws.SetPingHandler(func(appData string) error {
		if s.muted(id) {
			return nil
		}
		_ = ws.SetWriteDeadline(time.Now().Add(time.Second))
		return ws.WriteMessage(websocket.PongMessage, []byte(appData))
	})

	_, p, err := ws.ReadMessage()
	if err != nil {
		return
	}
	var hs handshakeFrame
	if err = json.Unmarshal(p, &hs); err != nil {
		return
	}

	s.mu.Lock()
	s.lastHandshake = hs
	s.mu.Unlock()

	if hs.Event != "handshake" || hs.Key != testHandshakeKey {
		_ = ws.WriteJSON(map[string]any{"ok": false, "message": "bad key"})
		return
	}
	if err = ws.WriteJSON(map[string]any{"ok": true}); err != nil {
		return
	}
	if reject {
		_ = ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "handshake failed"),
			time.Now().Add(time.Second))
		return
	}

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.received = append(s.received, string(msg))
		s.mu.Unlock()
	}
}

func (s *wsServer) muted(id int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return id <= s.muteUpTo
}

func (s *wsServer) muteCurrent() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.muteUpTo = s.accepted
}

func (s *wsServer) counts() (accepted, open int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted, s.open
}

func (s *wsServer) apiCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.apiHits
}

func (s *wsServer) handshake() handshakeFrame {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastHandshake
}

func (s *wsServer) messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.received...)
}

func (s *wsServer) setRejectWS(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectWS = v
}

func (s *wsServer) failAPI(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiStatus, s.apiBody = status, body
}

// fastTimers for hasten test
func fastTimers(t *testing.T) {
	t.Helper()
	t.Setenv("WS_PONG_WAIT", "400ms")
	t.Setenv("WS_PING_PERIOD", "50ms")
	t.Setenv("WS_RECONNECT_DELAY", "50ms")
}

func testPayload() *ConnectPayload {
	return &ConnectPayload{
		PayloadBase: PayloadBase{Service: "network"},
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestHandshakeSuccess(t *testing.T) {
	srv := newWSServer(t)
	t.Setenv("ENDPOINT", srv.http.URL)
	fastTimers(t)

	conn := NewConnection(testPayload())
	defer conn.close()

	waitFor(t, "websocket accepted", func() bool {
		accepted, _ := srv.counts()
		return accepted == 1
	})

	hs := srv.handshake()
	if hs.Event != "handshake" {
		t.Errorf("event = %q, want %q", hs.Event, "handshake")
	}
	if hs.Key != testHandshakeKey {
		t.Errorf("key = %q, want %q", hs.Key, testHandshakeKey)
	}
	if hs.Service != "network" {
		t.Errorf("service = %q, want %q", hs.Service, "network")
	}

	if got := conn.Response(); got == nil || !got.Ok {
		t.Errorf("Response() = %+v, want ok response", got)
	}

	conn.Send(map[string]string{"event": "ping-payload"})
	waitFor(t, "message delivered", func() bool { return len(srv.messages()) == 1 })
}

func TestHandshakeAPIStatusError(t *testing.T) {
	srv := newWSServer(t)
	srv.failAPI(http.StatusUnauthorized, "bad connect key")
	t.Setenv("ENDPOINT", srv.http.URL)

	c := newConnection(testPayload())
	defer c.close()

	err := c.connect(context.Background())
	if err == nil {
		t.Fatal("connect() = nil, want error")
	}

	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "bad connect key") {
		t.Errorf("err = %q, want status and body in message", err)
	}
	if accepted, _ := srv.counts(); accepted != 0 {
		t.Errorf("accepted = %d, want 0", accepted)
	}
}

func TestSlotsExhaustedIsRecognised(t *testing.T) {
	cases := []struct {
		name string
		err  *apiError
		want bool
	}{
		{"by code", &apiError{code: "nodes_limit_reached", message: "whatever"}, true},
		{"by message", &apiError{message: "the number of nodes has been reached"}, true},
		{"unrelated", &apiError{code: "bad_key", message: "invalid key"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := errors.Is(tc.err, errSlotsExhausted); got != tc.want {
				t.Errorf("errors.Is(%v, errSlotsExhausted) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestReconnectAfterServerClose(t *testing.T) {
	srv := newWSServer(t)
	t.Setenv("ENDPOINT", srv.http.URL)
	fastTimers(t)

	conn := NewConnection(testPayload())
	defer conn.close()

	waitFor(t, "first connection", func() bool {
		accepted, _ := srv.counts()
		return accepted == 1
	})

	// server mute
	srv.muteCurrent()

	waitFor(t, "reconnect", func() bool {
		accepted, _ := srv.counts()
		return accepted >= 2
	})

	// after reconnection again work
	before := len(srv.messages())
	waitFor(t, "message after reconnect", func() bool {
		conn.Send(map[string]string{"event": "after-reconnect"})
		return len(srv.messages()) > before
	})
}

func TestNoSocketLeakOnReconnect(t *testing.T) {
	srv := newWSServer(t)
	t.Setenv("ENDPOINT", srv.http.URL)
	fastTimers(t)

	conn := NewConnection(testPayload())
	defer conn.close()

	waitFor(t, "first connection", func() bool {
		accepted, open := srv.counts()
		return accepted == 1 && open == 1
	})

	goroutinesBase := runtime.NumGoroutine()

	const cycles = 5
	for i := 1; i <= cycles; i++ {
		srv.muteCurrent()

		waitFor(t, "reconnect", func() bool {
			accepted, _ := srv.counts()
			return accepted == i+1
		})

		// testing break connection
		waitFor(t, "old socket closed", func() bool {
			_, open := srv.counts()
			return open == 1
		})
	}

	if accepted, open := srv.counts(); open != 1 {
		t.Fatalf("open sockets = %d after %d reconnects (accepted %d), want 1", open, cycles, accepted)
	}

	// too reader and writer check break
	const slack = 6
	waitFor(t, "goroutines settled", func() bool {
		return runtime.NumGoroutine() <= goroutinesBase+slack
	})
	if got := runtime.NumGoroutine(); got > goroutinesBase+slack {
		t.Errorf("goroutines = %d after %d reconnects, base %d", got, cycles, goroutinesBase)
	}
}

func TestCloseIsIdempotentAndNonBlocking(t *testing.T) {
	srv := newWSServer(t)
	t.Setenv("ENDPOINT", srv.http.URL)
	fastTimers(t)

	conn := NewConnection(testPayload())
	waitFor(t, "connection", func() bool {
		accepted, _ := srv.counts()
		return accepted == 1
	})

	done := make(chan struct{})
	go func() {
		conn.close()
		conn.close() // test recall
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(closeGrace + 5*time.Second):
		t.Fatal("close() blocked")
	}

	// stop cycle reconnect
	apiBefore := srv.apiCalls()
	time.Sleep(300 * time.Millisecond)
	if got := srv.apiCalls(); got != apiBefore {
		t.Errorf("api calls after close: %d -> %d, want no reconnect attempts", apiBefore, got)
	}
	waitFor(t, "socket closed", func() bool {
		_, open := srv.counts()
		return open == 0
	})
}

// test deadlock writer and close() in reconnection
func TestCloseWithoutLiveSession(t *testing.T) {
	srv := newWSServer(t)
	t.Setenv("ENDPOINT", srv.http.URL)
	fastTimers(t)

	conn := NewConnection(testPayload())
	waitFor(t, "connection", func() bool {
		accepted, _ := srv.counts()
		return accepted == 1
	})

	// kill session and close API
	srv.failAPI(http.StatusInternalServerError, "down")
	srv.muteCurrent()
	waitFor(t, "reconnect loop", func() bool { return srv.apiCalls() >= 2 })

	done := make(chan struct{})
	go func() {
		conn.close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(closeGrace + 5*time.Second):
		t.Fatal("close() blocked while reconnecting")
	}
}

func TestSendNeverBlocks(t *testing.T) {
	srv := newWSServer(t)
	t.Setenv("ENDPOINT", srv.http.URL)
	fastTimers(t)

	c := newConnection(testPayload())
	defer c.close()

	done := make(chan int)
	go func() {
		sent := 0
		for i := 0; i < 1000; i++ {
			if c.Send(i) {
				sent++
			}
		}
		done <- sent
	}()

	select {
	case sent := <-done:
		if sent != cap(c.chanSend) {
			t.Errorf("sent = %d, want %d (buffer capacity)", sent, cap(c.chanSend))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send() blocked when writer is absent")
	}

	if c.dropped.Load() == 0 {
		t.Error("dropped counter = 0, want > 0")
	}
}

// test for nh: previous connect still active
func TestRejectedHandshakeIsThrottled(t *testing.T) {
	srv := newWSServer(t)
	t.Setenv("ENDPOINT", srv.http.URL)
	fastTimers(t)
	t.Setenv("WS_RECONNECT_DELAY", "200ms")

	srv.setRejectWS(true)

	conn := NewConnection(testPayload())
	defer conn.close()

	time.Sleep(2 * time.Second)

	accepted, _ := srv.counts()
	if accepted > 8 {
		t.Errorf("accepted = %d connections in 2s, want <= 8 (reconnect loop is not throttled)", accepted)
	}
	if accepted < 2 {
		t.Errorf("accepted = %d connections in 2s, want >= 2 (client stopped retrying)", accepted)
	}

	srv.setRejectWS(false)
	waitFor(t, "recovery after server stops rejecting", func() bool {
		_, open := srv.counts()
		return open == 1
	})
}

func TestStableSessionResetsBackoff(t *testing.T) {
	srv := newWSServer(t)
	t.Setenv("ENDPOINT", srv.http.URL)
	fastTimers(t)
	t.Setenv("WS_RECONNECT_DELAY", "100ms")

	conn := NewConnection(testPayload())
	defer conn.close()

	waitFor(t, "first connection", func() bool {
		accepted, _ := srv.counts()
		return accepted == 1
	})

	start := time.Now()
	srv.muteCurrent()
	waitFor(t, "reconnect", func() bool {
		accepted, _ := srv.counts()
		return accepted == 2
	})

	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("reconnect took %s, want fast recovery after a healthy session", elapsed)
	}
}

func TestSanePingPeriod(t *testing.T) {
	cases := []struct{ ping, pong, want time.Duration }{
		{30 * time.Second, 90 * time.Second, 30 * time.Second},
		{90 * time.Second, 90 * time.Second, 81 * time.Second},
		{120 * time.Second, 90 * time.Second, 81 * time.Second},
	}
	for _, tc := range cases {
		if got := sanePingPeriod(tc.ping, tc.pong); got != tc.want {
			t.Errorf("sanePingPeriod(%s, %s) = %s, want %s", tc.ping, tc.pong, got, tc.want)
		}
	}
}

func TestJitterStaysInRange(t *testing.T) {
	const d = time.Second
	for i := 0; i < 1000; i++ {
		got := jitter(d)
		if got < 800*time.Millisecond || got > 1200*time.Millisecond {
			t.Fatalf("jitter(%s) = %s, want within ±20%%", d, got)
		}
	}
}
