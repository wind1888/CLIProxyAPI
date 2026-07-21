// Package claude provides authentication functionality for Anthropic's Claude API.
// This file implements a custom HTTP transport using utls to bypass TLS fingerprinting.
package claude

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

const utlsConnectionSetupTimeout = 30 * time.Second

var errUTLSConnectionNotUsable = errors.New("new HTTP/2 connection cannot accept requests")

type pendingConnection struct {
	done chan struct{}
	err  error
}

// utlsRoundTripper implements http.RoundTripper using utls with Chrome fingerprint
// to bypass Cloudflare's TLS fingerprinting on Anthropic domains.
type utlsRoundTripper struct {
	// mu protects the connections map and pending map
	mu sync.Mutex
	// connections caches HTTP/2 client connections per host
	connections map[string]*http2.ClientConn
	// pending tracks hosts that are currently being connected to (prevents race condition)
	pending map[string]*pendingConnection
	// dialer is used to create network connections, supporting proxies
	dialer proxy.Dialer
}

// newUtlsRoundTripper creates a new utls-based round tripper with optional proxy support
func newUtlsRoundTripper(cfg *config.SDKConfig) *utlsRoundTripper {
	var dialer proxy.Dialer = &net.Dialer{
		Timeout:   utlsConnectionSetupTimeout,
		KeepAlive: 30 * time.Second,
	}
	if cfg != nil {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(cfg.ProxyURL)
		if errBuild != nil {
			log.Errorf("failed to configure proxy dialer for %q: %v", proxyutil.Redact(cfg.ProxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}

	return &utlsRoundTripper{
		connections: make(map[string]*http2.ClientConn),
		pending:     make(map[string]*pendingConnection),
		dialer:      dialer,
	}
}

// getOrCreateConnection gets an existing connection or creates a new one.
// It uses a per-host locking mechanism to prevent multiple goroutines from
// creating connections to the same host simultaneously.
func (t *utlsRoundTripper) getOrCreateConnection(ctx context.Context, key, host, addr string) (*http2.ClientConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	for {
		if errContext := ctx.Err(); errContext != nil {
			return nil, errContext
		}

		var stale *http2.ClientConn
		t.mu.Lock()
		if h2Conn := t.connections[key]; h2Conn != nil {
			// Reserve before returning so CloseIdleConnections cannot close the
			// connection in the small window before RoundTrip opens its stream.
			if h2Conn.ReserveNewRequest() {
				t.mu.Unlock()
				return h2Conn, nil
			}
			delete(t.connections, key)
			stale = h2Conn
		}

		if pending := t.pending[key]; pending != nil {
			t.mu.Unlock()
			closeHTTP2ClientConnIfIdle(stale)
			select {
			case <-pending.done:
				// A connection failure caused solely by the creating request's
				// cancellation must not poison independent waiters.
				if pending.err != nil &&
					!errors.Is(pending.err, context.Canceled) &&
					!errors.Is(pending.err, context.DeadlineExceeded) {
					return nil, pending.err
				}
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		pending := &pendingConnection{done: make(chan struct{})}
		t.pending[key] = pending
		t.mu.Unlock()
		closeHTTP2ClientConnIfIdle(stale)

		h2Conn, errCreate := t.createConnection(ctx, host, addr)
		if errCreate == nil && !h2Conn.ReserveNewRequest() {
			closeHTTP2ClientConn(h2Conn)
			h2Conn = nil
			errCreate = errUTLSConnectionNotUsable
		}

		var replaced *http2.ClientConn
		t.mu.Lock()
		if t.pending[key] == pending {
			delete(t.pending, key)
		}
		if errCreate == nil {
			replaced = t.connections[key]
			t.connections[key] = h2Conn
		}
		pending.err = errCreate
		close(pending.done)
		t.mu.Unlock()
		if replaced != h2Conn {
			closeHTTP2ClientConnIfIdle(replaced)
		}

		return h2Conn, errCreate
	}
}

// createConnection creates a new HTTP/2 connection with Chrome TLS fingerprint.
// Chrome's TLS fingerprint is closer to Node.js/OpenSSL (which real Claude Code uses)
// than Firefox, reducing the mismatch between TLS layer and HTTP headers.
func (t *utlsRoundTripper) createConnection(ctx context.Context, host, addr string) (*http2.ClientConn, error) {
	setupCtx, cancel := context.WithTimeout(ctx, utlsConnectionSetupTimeout)
	defer cancel()

	conn, err := t.dialContext(setupCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{ServerName: host}
	tlsConn := tls.UClient(conn, tlsConfig, tls.HelloChrome_Auto)

	if errHandshake := tlsConn.HandshakeContext(setupCtx); errHandshake != nil {
		_ = conn.Close()
		return nil, errHandshake
	}

	tr := &http2.Transport{StrictMaxConcurrentStreams: true}
	h2Conn, errHTTP2 := tr.NewClientConn(tlsConn)
	if errHTTP2 != nil {
		_ = tlsConn.Close()
		return nil, errHTTP2
	}

	return h2Conn, nil
}

// dialContext uses a native context-aware dialer where possible. Legacy proxy
// dialers are isolated in a goroutine; an eventually returned connection is
// closed if the request has already been canceled.
func (t *utlsRoundTripper) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if contextDialer, ok := t.dialer.(proxy.ContextDialer); ok {
		return contextDialer.DialContext(ctx, network, addr)
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult)
	go func() {
		conn, errDial := t.dialer.Dial(network, addr)
		result := dialResult{conn: conn, err: errDial}
		select {
		case resultCh <- result:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()

	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// RoundTrip implements http.RoundTripper
func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	hostname := req.URL.Hostname()
	addr := req.URL.Host
	if req.URL.Port() == "" {
		addr = net.JoinHostPort(hostname, "443")
	}
	key := strings.ToLower(req.URL.Host)

	h2Conn, err := t.getOrCreateConnection(req.Context(), key, hostname, addr)
	if err != nil {
		return nil, err
	}

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		// Remove and close connections that HTTP/2 has marked unusable. A
		// canceled individual stream does not force unrelated streams off an
		// otherwise healthy multiplexed connection.
		if !h2Conn.CanTakeNewRequest() {
			removed := false
			t.mu.Lock()
			if t.connections[key] == h2Conn {
				delete(t.connections, key)
				removed = true
			}
			t.mu.Unlock()
			if removed {
				closeHTTP2ClientConnIfIdle(h2Conn)
			}
		}
		return nil, err
	}

	return resp, nil
}

// CloseIdleConnections closes cached HTTP/2 connections that have no active,
// reserved, or pending streams. It intentionally leaves in-flight setup and
// active multiplexed requests alone.
func (t *utlsRoundTripper) CloseIdleConnections() {
	var idle []*http2.ClientConn
	t.mu.Lock()
	for key, h2Conn := range t.connections {
		state := h2Conn.State()
		if state.StreamsActive == 0 && state.StreamsReserved == 0 && state.StreamsPending == 0 {
			delete(t.connections, key)
			idle = append(idle, h2Conn)
		}
	}
	t.mu.Unlock()

	for _, h2Conn := range idle {
		closeHTTP2ClientConn(h2Conn)
	}
}

func closeHTTP2ClientConn(h2Conn *http2.ClientConn) {
	if h2Conn != nil {
		_ = h2Conn.Close()
	}
}

func closeHTTP2ClientConnIfIdle(h2Conn *http2.ClientConn) {
	if h2Conn == nil {
		return
	}
	state := h2Conn.State()
	if state.StreamsActive == 0 && state.StreamsReserved == 0 && state.StreamsPending == 0 {
		closeHTTP2ClientConn(h2Conn)
	}
}

// NewAnthropicHttpClient creates an HTTP client that bypasses TLS fingerprinting
// for Anthropic domains by using utls with Chrome fingerprint.
// It accepts optional SDK configuration for proxy settings.
func NewAnthropicHttpClient(cfg *config.SDKConfig) *http.Client {
	return &http.Client{
		Transport: newUtlsRoundTripper(cfg),
	}
}
