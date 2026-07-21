package claude

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestUTLSConnectionPendingSharesFailureAndWaiterHonorsContext(t *testing.T) {
	wantErr := errors.New("synthetic dial failure")
	dialer := &blockingContextDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
		err:     wantErr,
	}
	transport := &utlsRoundTripper{
		connections: make(map[string]*http2.ClientConn),
		pending:     make(map[string]*pendingConnection),
		dialer:      dialer,
	}

	ownerResult := make(chan error, 1)
	go func() {
		_, err := transport.getOrCreateConnection(context.Background(), "api.example:443", "api.example", "api.example:443")
		ownerResult <- err
	}()
	<-dialer.started

	waiterBase, cancelWaiter := context.WithCancel(context.Background())
	waiterContext := newObservedContext(waiterBase)
	waiterResult := make(chan error, 1)
	go func() {
		_, err := transport.getOrCreateConnection(waiterContext, "api.example:443", "api.example", "api.example:443")
		waiterResult <- err
	}()
	<-waiterContext.observed
	cancelWaiter()
	if err := receiveError(t, waiterResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v, want context.Canceled", err)
	}
	if calls := dialer.calls.Load(); calls != 1 {
		t.Fatalf("dial calls after canceled waiter = %d, want 1", calls)
	}

	sharedContext := newObservedContext(context.Background())
	sharedResult := make(chan error, 1)
	go func() {
		_, err := transport.getOrCreateConnection(sharedContext, "api.example:443", "api.example", "api.example:443")
		sharedResult <- err
	}()
	<-sharedContext.observed
	close(dialer.release)

	if err := receiveError(t, ownerResult); !errors.Is(err, wantErr) {
		t.Fatalf("owner error = %v, want %v", err, wantErr)
	}
	if err := receiveError(t, sharedResult); !errors.Is(err, wantErr) {
		t.Fatalf("shared waiter error = %v, want %v", err, wantErr)
	}
	if calls := dialer.calls.Load(); calls != 1 {
		t.Fatalf("shared failure dial calls = %d, want 1", calls)
	}

	if _, err := transport.getOrCreateConnection(context.Background(), "api.example:443", "api.example", "api.example:443"); !errors.Is(err, wantErr) {
		t.Fatalf("retry error = %v, want %v", err, wantErr)
	}
	if calls := dialer.calls.Load(); calls != 2 {
		t.Fatalf("retry dial calls = %d, want 2", calls)
	}
}

func TestUTLSCanceledConnectionOwnerDoesNotPoisonWaiter(t *testing.T) {
	wantErr := errors.New("second dial failure")
	dialer := &cancelThenFailContextDialer{
		firstStarted:  make(chan struct{}),
		secondStarted: make(chan struct{}),
		err:           wantErr,
	}
	transport := &utlsRoundTripper{
		connections: make(map[string]*http2.ClientConn),
		pending:     make(map[string]*pendingConnection),
		dialer:      dialer,
	}

	ownerContext, cancelOwner := context.WithCancel(context.Background())
	ownerResult := make(chan error, 1)
	go func() {
		_, err := transport.getOrCreateConnection(ownerContext, "api.example:443", "api.example", "api.example:443")
		ownerResult <- err
	}()
	<-dialer.firstStarted

	waiterContext := newObservedContext(context.Background())
	waiterResult := make(chan error, 1)
	go func() {
		_, err := transport.getOrCreateConnection(waiterContext, "api.example:443", "api.example", "api.example:443")
		waiterResult <- err
	}()
	<-waiterContext.observed
	cancelOwner()

	if err := receiveError(t, ownerResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("owner error = %v, want context.Canceled", err)
	}
	select {
	case <-dialer.secondStarted:
	case <-time.After(time.Second):
		t.Fatal("independent waiter did not retry after owner cancellation")
	}
	if err := receiveError(t, waiterResult); !errors.Is(err, wantErr) {
		t.Fatalf("waiter retry error = %v, want %v", err, wantErr)
	}
	if calls := dialer.calls.Load(); calls != 2 {
		t.Fatalf("dial calls = %d, want 2", calls)
	}
}

func TestUTLSLegacyDialerClosesConnectionReturnedAfterCancellation(t *testing.T) {
	dialer := &blockingLegacyDialer{
		started:    make(chan struct{}),
		release:    make(chan struct{}),
		serverConn: make(chan net.Conn, 1),
	}
	transport := &utlsRoundTripper{dialer: dialer}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := transport.dialContext(ctx, "tcp", "api.example:443")
		result <- err
	}()
	<-dialer.started
	cancel()
	if err := receiveError(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("dialContext() error = %v, want context.Canceled", err)
	}

	close(dialer.release)
	serverConn := <-dialer.serverConn
	defer serverConn.Close()
	if err := serverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return
		}
		t.Fatalf("set peer deadline: %v", err)
	}
	buffer := make([]byte, 1)
	if _, err := serverConn.Read(buffer); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("peer read error = %v, want EOF from closed canceled connection", err)
	}
}

func TestUTLSCloseIdleConnectionsRemovesAndClosesIdleHTTP2Connection(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		(&http2.Server{}).ServeConn(serverSide, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		})
	}()

	h2Conn, errClient := (&http2.Transport{}).NewClientConn(clientSide)
	if errClient != nil {
		_ = clientSide.Close()
		_ = serverSide.Close()
		t.Fatalf("create HTTP/2 client connection: %v", errClient)
	}
	transport := &utlsRoundTripper{
		connections: map[string]*http2.ClientConn{"api.example:443": h2Conn},
		pending:     make(map[string]*pendingConnection),
	}
	if !h2Conn.ReserveNewRequest() {
		t.Fatal("ReserveNewRequest() = false on new HTTP/2 connection")
	}
	transport.CloseIdleConnections()
	transport.mu.Lock()
	reservedRemaining := len(transport.connections)
	transport.mu.Unlock()
	if reservedRemaining != 1 {
		t.Fatalf("cached connections while request is reserved = %d, want 1", reservedRemaining)
	}

	req, errRequest := http.NewRequest(http.MethodGet, "https://api.example/test", nil)
	if errRequest != nil {
		t.Fatalf("create request: %v", errRequest)
	}
	resp, errRoundTrip := h2Conn.RoundTrip(req)
	if errRoundTrip != nil {
		t.Fatalf("HTTP/2 RoundTrip() error = %v", errRoundTrip)
	}
	if errCloseBody := resp.Body.Close(); errCloseBody != nil {
		t.Fatalf("close response body: %v", errCloseBody)
	}

	transport.CloseIdleConnections()

	transport.mu.Lock()
	remaining := len(transport.connections)
	transport.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("cached connections after CloseIdleConnections() = %d, want 0", remaining)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		_ = serverSide.Close()
		t.Fatal("HTTP/2 server did not observe idle connection close")
	}
}

type blockingContextDialer struct {
	started chan struct{}
	release chan struct{}
	err     error
	calls   atomic.Int32
	once    sync.Once
}

func (d *blockingContextDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *blockingContextDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.calls.Add(1)
	d.once.Do(func() { close(d.started) })
	select {
	case <-d.release:
		return nil, d.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type cancelThenFailContextDialer struct {
	firstStarted  chan struct{}
	secondStarted chan struct{}
	err           error
	calls         atomic.Int32
}

func (d *cancelThenFailContextDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *cancelThenFailContextDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	switch d.calls.Add(1) {
	case 1:
		close(d.firstStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	case 2:
		close(d.secondStarted)
		return nil, d.err
	default:
		return nil, d.err
	}
}

type blockingLegacyDialer struct {
	started    chan struct{}
	release    chan struct{}
	serverConn chan net.Conn
	once       sync.Once
}

func (d *blockingLegacyDialer) Dial(_, _ string) (net.Conn, error) {
	d.once.Do(func() { close(d.started) })
	<-d.release
	clientSide, serverSide := net.Pipe()
	d.serverConn <- serverSide
	return clientSide, nil
}

type observedContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func newObservedContext(parent context.Context) *observedContext {
	return &observedContext{Context: parent, observed: make(chan struct{})}
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func receiveError(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for result")
		return nil
	}
}
