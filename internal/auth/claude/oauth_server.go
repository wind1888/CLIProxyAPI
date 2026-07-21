// Package claude provides authentication and token management functionality
// for Anthropic's Claude AI services. It handles OAuth2 token storage, serialization,
// and retrieval for maintaining authenticated sessions with the Claude API.
package claude

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// OAuthServer handles the local HTTP server for OAuth callbacks.
// It listens for the authorization code response from the OAuth provider
// and captures the necessary parameters to complete the authentication flow.
type OAuthServer struct {
	// server is the underlying HTTP server instance
	server *http.Server
	// listener is bound synchronously so port 0 can resolve to an available loopback port.
	listener net.Listener
	// port is the port number on which the server listens
	port int
	// resultChan is a channel for sending OAuth results
	resultChan chan *OAuthResult
	// errorChan is a channel for sending OAuth errors
	errorChan chan error
	// completionChan releases the held callback response after token exchange.
	completionChan chan oauthCallbackCompletion
	// expectedState is the state generated for this OAuth attempt.
	expectedState string
	// pendingResponse reports whether a valid callback is waiting for exchange.
	pendingResponse bool
	// successURL is selected from the token response scope before completion.
	successURL string
	// mu is a mutex for protecting server state
	mu sync.Mutex
	// running indicates whether the server is currently running
	running bool
}

type oauthCallbackCompletion struct {
	err error
}

// OAuthResult contains the result of the OAuth callback.
// It holds either the authorization code and state for successful authentication
// or an error message if the authentication failed.
type OAuthResult struct {
	// Code is the authorization code received from the OAuth provider
	Code string
	// State is the state parameter used to prevent CSRF attacks
	State string
	// Error contains any error message if the OAuth flow failed
	Error string
}

// NewOAuthServer creates a new OAuth callback server.
// It initializes the server with the specified port and creates channels
// for handling OAuth results and errors.
//
// Parameters:
//   - port: The port number on which the server should listen
//
// Returns:
//   - *OAuthServer: A new OAuthServer instance
func NewOAuthServer(port int) *OAuthServer {
	return &OAuthServer{
		port:           port,
		resultChan:     make(chan *OAuthResult, 1),
		errorChan:      make(chan error, 1),
		completionChan: make(chan oauthCallbackCompletion, 1),
		successURL:     OAuthSuccessURL,
	}
}

// Start starts the OAuth callback server.
// It sets up the official callback endpoint,
// and begins listening on the specified port.
//
// Returns:
//   - error: An error if the server fails to start
func (s *OAuthServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server is already running")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.handleCallback(w, r)
	})

	listener, errListen := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", s.port))
	if errListen != nil {
		return fmt.Errorf("listen on Claude OAuth loopback port %d: %w", s.port, errListen)
	}
	tcpAddr, okTCP := listener.Addr().(*net.TCPAddr)
	if !okTCP || tcpAddr.Port <= 0 {
		_ = listener.Close()
		return fmt.Errorf("resolve Claude OAuth loopback port")
	}
	s.port = tcpAddr.Port
	s.listener = listener
	s.server = &http.Server{
		Addr:        fmt.Sprintf("127.0.0.1:%d", s.port),
		Handler:     handler,
		ReadTimeout: 10 * time.Second,
		// Token exchange plus the best-effort profile lookup can exceed 45 seconds.
		// Keep the browser response open long enough for the complete OAuth path.
		WriteTimeout: 75 * time.Second,
	}
	server := s.server

	s.running = true

	// Start server in goroutine
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			s.errorChan <- fmt.Errorf("server failed to start: %w", err)
		}
	}()

	return nil
}

// Stop gracefully stops the OAuth callback server.
// It performs a graceful shutdown of the HTTP server with a timeout.
//
// Parameters:
//   - ctx: The context for controlling the shutdown process
//
// Returns:
//   - error: An error if the server fails to stop gracefully
func (s *OAuthServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running || s.server == nil {
		s.mu.Unlock()
		return nil
	}
	server := s.server
	s.running = false
	s.server = nil
	s.listener = nil
	s.pendingResponse = false
	s.mu.Unlock()

	log.Debug("Stopping OAuth callback server")
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

// WaitForCallback waits for the OAuth callback with a timeout.
// It blocks until either an OAuth result is received, an error occurs,
// or the specified timeout is reached.
//
// Parameters:
//   - timeout: The maximum time to wait for the callback
//
// Returns:
//   - *OAuthResult: The OAuth result if successful
//   - error: An error if the callback times out or an error occurs
func (s *OAuthServer) WaitForCallback(timeout time.Duration) (*OAuthResult, error) {
	return s.WaitForCallbackContext(context.Background(), timeout)
}

// WaitForCallbackContext waits for a callback while also honoring caller
// cancellation. This prevents a canceled CLI login from waiting for the full
// callback timeout.
func (s *OAuthServer) WaitForCallbackContext(ctx context.Context, timeout time.Duration) (*OAuthResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result := <-s.resultChan:
		return result, nil
	case err := <-s.errorChan:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("timeout waiting for OAuth callback")
	}
}

// handleCallback handles the OAuth callback endpoint.
// It extracts the authorization code and state from the callback URL,
// validates the parameters, and sends the result to the waiting channel.
//
// Parameters:
//   - w: The HTTP response writer
//   - r: The HTTP request
func (s *OAuthServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	log.Debug("Received OAuth callback")

	query := r.URL.Query()
	code := query.Get("code")
	state := query.Get("state")

	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Authorization code not found"))
		s.sendError(fmt.Errorf("authorization code not found"))
		return
	}

	s.mu.Lock()
	expectedState := s.expectedState
	s.mu.Unlock()
	if state == "" || expectedState == "" || state != expectedState {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Invalid state parameter"))
		s.sendError(fmt.Errorf("invalid state parameter"))
		return
	}

	result := &OAuthResult{
		Code:  code,
		State: state,
	}
	s.mu.Lock()
	s.pendingResponse = true
	s.mu.Unlock()
	if !s.sendResult(result) {
		s.mu.Lock()
		s.pendingResponse = false
		s.mu.Unlock()
		w.WriteHeader(http.StatusConflict)
		return
	}
	// Stop accepting a competing callback as soon as this authorization code is
	// resolved, while leaving the current HTTP response open for token exchange.
	s.mu.Lock()
	listener := s.listener
	s.listener = nil
	s.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}

	select {
	case completion := <-s.completionChan:
		s.mu.Lock()
		s.pendingResponse = false
		s.mu.Unlock()
		if completion.err != nil {
			// Claude Code's native listener releases a failed exchange through the
			// same hosted completion page; the CLI itself reports the real error.
			w.Header().Set("Location", OAuthSuccessURL)
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusFound)
			return
		}
		s.mu.Lock()
		successURL := s.successURL
		s.mu.Unlock()
		if strings.TrimSpace(successURL) == "" {
			successURL = OAuthSuccessURL
		}
		w.Header().Set("Location", successURL)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusFound)
	case <-r.Context().Done():
		s.mu.Lock()
		s.pendingResponse = false
		s.mu.Unlock()
	}
}

func (s *OAuthServer) sendError(err error) {
	if err == nil {
		return
	}
	select {
	case s.errorChan <- err:
	default:
	}
}

// sendResult sends the OAuth result to the waiting channel.
// It ensures that the result is sent without blocking the handler.
//
// Parameters:
//   - result: The OAuth result to send
func (s *OAuthServer) sendResult(result *OAuthResult) bool {
	select {
	case s.resultChan <- result:
		log.Debug("OAuth result sent to channel")
		return true
	default:
		log.Warn("OAuth result channel is full, result dropped")
		return false
	}
}

// IsRunning returns whether the server is currently running.
//
// Returns:
//   - bool: True if the server is running, false otherwise
func (s *OAuthServer) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Port returns the bound loopback port after Start succeeds.
func (s *OAuthServer) Port() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
}

// RedirectURI returns the official localhost callback form for the bound port.
func (s *OAuthServer) RedirectURI() string {
	return fmt.Sprintf("http://localhost:%d/callback", s.Port())
}

// SetExpectedState configures the state that the loopback callback must carry.
func (s *OAuthServer) SetExpectedState(state string) {
	s.mu.Lock()
	s.expectedState = state
	s.mu.Unlock()
}

// SetSuccessURL selects the final redirect after token exchange.
func (s *OAuthServer) SetSuccessURL(successURL string) {
	s.mu.Lock()
	s.successURL = strings.TrimSpace(successURL)
	s.mu.Unlock()
}

// HasPendingResponse reports whether a valid callback is waiting for exchange.
func (s *OAuthServer) HasPendingResponse() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingResponse
}

// CompleteCallback releases a held callback after token exchange finishes.
func (s *OAuthServer) CompleteCallback() {
	select {
	case s.completionChan <- oauthCallbackCompletion{}:
	default:
	}
}

// FailCallback releases a held browser response after a failed exchange. The
// native Claude Code listener still redirects the browser to its hosted finish
// page while the CLI reports the exchange error.
func (s *OAuthServer) FailCallback(err error) {
	if err == nil {
		err = errors.New("token exchange failed")
	}
	select {
	case s.completionChan <- oauthCallbackCompletion{err: err}:
	default:
	}
}
