package claude

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestOAuthServerUsesDynamicIPv4LoopbackPort(t *testing.T) {
	server := NewOAuthServer(0)
	server.SetExpectedState("oauth-state")
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		server.CompleteCallback()
		stopCtx, cancelStop := context.WithTimeout(context.Background(), time.Second)
		defer cancelStop()
		_ = server.Stop(stopCtx)
	})
	if !server.IsRunning() {
		t.Fatal("server is not running after Start")
	}
	if got := server.server.WriteTimeout; got < 75*time.Second {
		t.Fatalf("WriteTimeout = %s, want at least 75s", got)
	}
	if server.Port() <= 0 {
		t.Fatalf("bound port = %d", server.Port())
	}
	if got, want := server.RedirectURI(), fmt.Sprintf("http://localhost:%d/callback", server.Port()); got != want {
		t.Fatalf("RedirectURI() = %q, want %q", got, want)
	}
	conn, errDial := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", server.Port()), time.Second)
	if errDial != nil {
		t.Fatalf("loopback listener is not reachable: %v", errDial)
	}
	_ = conn.Close()

	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	for _, test := range []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string
	}{
		{name: "non callback", path: "/success", wantStatus: http.StatusNotFound},
		{name: "missing code", path: "/callback?state=oauth-state", wantStatus: http.StatusBadRequest, wantBody: "Authorization code not found"},
		{name: "provider error without code", path: "/callback?error=access_denied&error_description=cancelled&state=oauth-state", wantStatus: http.StatusBadRequest, wantBody: "Authorization code not found"},
		{name: "invalid state", path: "/callback?code=authorization-code&state=wrong", wantStatus: http.StatusBadRequest, wantBody: "Invalid state parameter"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resp, errGet := client.Get(fmt.Sprintf("http://localhost:%d%s", server.Port(), test.path))
			if errGet != nil {
				t.Fatalf("GET error = %v", errGet)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != test.wantStatus || string(body) != test.wantBody {
				t.Fatalf("response = status %d body %q, want status %d body %q", resp.StatusCode, body, test.wantStatus, test.wantBody)
			}
			if test.path != "/success" {
				if _, errWait := server.WaitForCallback(time.Second); errWait == nil {
					t.Fatal("invalid callback did not terminate the OAuth wait")
				}
			}
		})
	}

	responseCh := make(chan *http.Response, 1)
	errorCh := make(chan error, 1)
	go func() {
		resp, errGet := client.Get(server.RedirectURI() + "?code=authorization-code&state=oauth-state")
		if errGet != nil {
			errorCh <- errGet
			return
		}
		responseCh <- resp
	}()
	result, errWait := server.WaitForCallback(time.Second)
	if errWait != nil {
		t.Fatalf("WaitForCallback() error = %v", errWait)
	}
	if result.Code != "authorization-code" || result.State != "oauth-state" || result.Error != "" {
		t.Fatalf("callback result = %#v", result)
	}
	if !server.HasPendingResponse() {
		t.Fatal("valid callback response was not held pending token exchange")
	}
	select {
	case resp := <-responseCh:
		_ = resp.Body.Close()
		t.Fatal("callback response completed before token exchange")
	case errGet := <-errorCh:
		t.Fatalf("GET callback error = %v", errGet)
	case <-time.After(20 * time.Millisecond):
	}
	server.CompleteCallback()
	var resp *http.Response
	select {
	case resp = <-responseCh:
	case errGet := <-errorCh:
		t.Fatalf("GET callback error = %v", errGet)
	case <-time.After(time.Second):
		t.Fatal("callback response did not complete after token exchange")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != OAuthSuccessURL {
		t.Fatalf("callback Location = %q, want %q", got, OAuthSuccessURL)
	}
	if body, _ := io.ReadAll(resp.Body); len(body) != 0 {
		t.Fatalf("callback body = %q, want empty", body)
	}

	stopCtx, cancelStop := context.WithTimeout(context.Background(), time.Second)
	defer cancelStop()
	if errStop := server.Stop(stopCtx); errStop != nil {
		t.Fatalf("Stop() error = %v", errStop)
	}
	if server.IsRunning() {
		t.Fatal("server is still running after Stop")
	}
	if errStopAgain := server.Stop(stopCtx); errStopAgain != nil {
		t.Fatalf("second Stop() error = %v", errStopAgain)
	}
}

func TestOAuthServerFailureRedirectMatchesClaudeCode(t *testing.T) {
	server := NewOAuthServer(0)
	server.SetExpectedState("oauth-state")
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		server.FailCallback(errors.New("test cleanup"))
		stopCtx, cancelStop := context.WithTimeout(context.Background(), time.Second)
		defer cancelStop()
		_ = server.Stop(stopCtx)
	})

	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	responseCh := make(chan *http.Response, 1)
	errorCh := make(chan error, 1)
	go func() {
		resp, errGet := client.Get(server.RedirectURI() + "?code=authorization-code&state=oauth-state")
		if errGet != nil {
			errorCh <- errGet
			return
		}
		responseCh <- resp
	}()

	if _, errWait := server.WaitForCallbackContext(context.Background(), time.Second); errWait != nil {
		t.Fatalf("WaitForCallbackContext() error = %v", errWait)
	}
	server.FailCallback(errors.New("token exchange rejected"))

	select {
	case resp := <-responseCh:
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("callback status = %d, want %d", resp.StatusCode, http.StatusFound)
		}
		if got := resp.Header.Get("Location"); got != OAuthSuccessURL {
			t.Fatalf("callback Location = %q, want %q", got, OAuthSuccessURL)
		}
		if len(body) != 0 {
			t.Fatalf("callback body = %q, want empty", body)
		}
	case errGet := <-errorCh:
		t.Fatalf("GET callback error = %v", errGet)
	case <-time.After(time.Second):
		t.Fatal("callback response did not report token exchange failure")
	}
}

func TestOAuthServerWaitForCallbackHonorsContext(t *testing.T) {
	server := NewOAuthServer(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	_, err := server.WaitForCallbackContext(ctx, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForCallbackContext() error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled callback wait took %s", elapsed)
	}
}
