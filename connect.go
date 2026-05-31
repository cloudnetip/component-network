package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"time"
)

const writeWait = 8 * time.Second
const pongWait = 180 * time.Second
const pingPeriod = (pongWait * 9) / 10

type ResponseBase struct {
	Ok           bool   `json:"ok"`
	Message      string `json:"message"`
	EndpointIP   string `json:"endpointIP"`
	EndpointPath string `json:"endpointPath"`
	HandshakeKey string `json:"handshakeKey"`
}

type PayloadBase struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
}

type Connection struct {
	destroy   chan struct{}
	reconnect chan struct{}
	client    *http.Client
	ws        *websocket.Conn
	payload   *ConnectPayload
	response  *ConnectResponse
	chanSend  chan any
	chanLive  chan []byte
}

func NewConnection(cp *ConnectPayload) *Connection {
	c := &Connection{
		destroy:   make(chan struct{}),
		reconnect: make(chan struct{}),
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 6 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				MaxConnsPerHost:       20,
				IdleConnTimeout:       60 * time.Second,
			},
			Timeout: 8 * time.Second,
		},
		payload:  cp,
		chanSend: make(chan any, 16),
		chanLive: make(chan []byte, 16),
	}
	log.Println("[connect] started")
	for {
		err := c.connect()
		if err != nil {
			c.degrade(err, false)
			continue
		}
		break
	}
	go c.maintain()
	return c
}

func (c *Connection) Response() *ConnectResponse {
	return c.response
}

func (c *Connection) maintain() {
	log.Println("[connect] maintenance")
	for range c.reconnect {
		log.Println("[connect] reconnection")
		err := c.connect()
		if err != nil {
			go c.degrade(err, true)
		}
	}
}

func (c *Connection) connect() error {
	var err error
	c.payload.Hostname, err = os.Hostname()
	if err != nil {
		c.fatal(errors.New("hostname err: " + err.Error()))
	}
	plJs, err := json.Marshal(c.payload)
	if err != nil {
		c.fatal(errors.New("marshal payload err: " + err.Error()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 16*time.Second)
	defer cancel()

	endpoint := os.Getenv("ENDPOINT")
	if endpoint == "" {
		endpoint = "https://cloudnetip.com/api"
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		endpoint+"/nodes/handshake/v2", bytes.NewReader(plJs))
	if err != nil {
		c.fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Key", os.Getenv("CONNECT_KEY"))
	req.Header.Set("X-Version", os.Getenv("VERSION"))
	req.Header.Set("X-Version-Hash", os.Getenv("VERSION_HASH"))

	if logger.debug {
		logger.Debugf("[connect] try connect to api... payload: %+v x-version: %q x-version-hash: %q",
			c.payload, os.Getenv("VERSION"), os.Getenv("VERSION_HASH"))

		var start = time.Now()
		trace := &httptrace.ClientTrace{
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
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	}

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(res.Body)

	if res.StatusCode >= 500 {
		return fmt.Errorf("response status: %s", res.Status)
	}

	c.response = new(ConnectResponse)
	err = json.NewDecoder(res.Body).Decode(c.response)
	if err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	if !c.response.Ok {
		return errors.New("api message: " + c.response.Message)
	}

	logger.Debugf("[connect] try connect to ws... endpoint ip: %q endpoint path: %q",
		c.response.EndpointIP, c.response.EndpointPath)

	c.ws = nil

	if c.response.EndpointIP == "" {
		// usual connect
		c.ws, _, err = websocket.DefaultDialer.DialContext(ctx, c.response.EndpointPath, nil)
		if err != nil {
			return fmt.Errorf("dial native: %w", err)
		}
	} else {
		// connect with replace ip
		dialer := websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 45 * time.Second,
			NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					log.Println("[connect] parse addr dial, err:", err)
				} else {
					addr = c.response.EndpointIP + ":" + port
				}
				netDialer := &net.Dialer{
					Timeout: 12 * time.Second,
				}
				return netDialer.DialContext(ctx, network, addr)
			},
		}

		c.ws, _, err = dialer.DialContext(ctx, c.response.EndpointPath, nil)
		if err != nil {
			return fmt.Errorf("dial modified: %w", err)
		}
	}

	_ = c.ws.SetReadDeadline(time.Now().Add(pongWait))
	_ = c.ws.SetWriteDeadline(time.Now().Add(writeWait))

	logger.Debugf("[connect] send handshake...")

	err = c.ws.WriteJSON(struct {
		Event   string `json:"event"`
		Key     string `json:"key"`
		Service string `json:"service"`
	}{
		"handshake",
		c.response.HandshakeKey,
		c.payload.Service,
	})
	if err != nil {
		_ = c.ws.Close()
		return fmt.Errorf("handshake: %w", err)
	}

	logger.Debugf("[connect] read handshake...")

	for {
		_, _, err = c.ws.ReadMessage()
		if err != nil {
			_ = c.ws.Close()
			return fmt.Errorf("handshake: %w", err)
		}
		log.Println("[connect] handshake successful")
		break
	}

	ctx, cancel = context.WithCancel(context.Background())
	go c.writer(ctx)
	go c.reader(cancel)

	return nil
}

func (c *Connection) reader(cancel context.CancelFunc) {
	defer func() {
		cancel()
	}()
	// handler get pong
	c.ws.SetPongHandler(func(string) error {
		_ = c.ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		messageType, r, err := c.ws.NextReader()
		if err != nil {
			logger.Debug("[connect] read pump err:", err)
			return
		}
		p, err := io.ReadAll(r)
		if err != nil {
			log.Printf("[connect] read pump: msg type: %d read all err: %s", messageType, err)
			return
		}
		select {
		case c.chanLive <- p:
		default:
			log.Println("[connect] notice: live chan is throttling")
		}
	}
}

func (c *Connection) writer(ctx context.Context) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
	}()
	for {
		select {
		case <-ctx.Done():
			go c.degrade(fmt.Errorf("reader context done"), true)
			return
		case message, ok := <-c.chanSend:
			_ = c.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				go c.degrade(fmt.Errorf("write pump: hub closed the channel"), true)
				return
			}

			wErr := c.ws.WriteJSON(message)
			if wErr != nil {
				go c.degrade(fmt.Errorf("write pump err: %w", wErr), true)
				return
			}
		case <-ticker.C:
			logger.Debug("[connect] write pump: send ping")
			// send ping
			_ = c.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				go c.degrade(fmt.Errorf("write pump: ticker write ping, err: %w", err), true)
				return
			}
		case <-c.destroy:
			err := c.ws.WriteMessage(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("[connect] write pump close err:", err)
				return
			}
			err = c.ws.Close()
			if err != nil {
				log.Println("[connect] close conn err:", err)
			}
			return
		}
	}
}

func (c *Connection) close() {
	c.destroy <- struct{}{}
}

func (c *Connection) fatal(err error) {
	log.Println("[connect] fatal: shutting down in 5 seconds, handshake request err:", err)
	time.Sleep(5 * time.Second)
	os.Exit(1)
}

func (c *Connection) degrade(err error, reconnect bool) {
	log.Println("[connect] failure, err:", err)
	if err != nil {
		if strings.Contains(err.Error(), "number of nodes has been reached") {
			log.Println("[connect] trying to reconnect after waiting 5 minutes")
			time.Sleep(5 * time.Minute)
		} else {
			log.Println("[connect] trying to reconnect after waiting 3 seconds")
			time.Sleep(3 * time.Second)
		}
	}
	if reconnect {
		select {
		case c.reconnect <- struct{}{}:
			logger.Debug("[connect] send signal reconnect")
		default:
			logger.Debug("[connect] skip! signal reconnect")
		}
	}
}
