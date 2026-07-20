package claude

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestClaudeOAuthEndpointsMatchClaudeCode(t *testing.T) {
	if AuthURL != "https://claude.com/cai/oauth/authorize" {
		t.Fatalf("AuthURL = %q", AuthURL)
	}
	if TokenURL != "https://platform.claude.com/v1/oauth/token" {
		t.Fatalf("TokenURL = %q", TokenURL)
	}
	if APIBaseURL != "https://api.anthropic.com" {
		t.Fatalf("APIBaseURL = %q", APIBaseURL)
	}
	if OAuthScope != "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload" {
		t.Fatalf("OAuthScope = %q", OAuthScope)
	}

	authURL, returnedState, err := (&ClaudeAuth{}).GenerateAuthURL("state-value", &PKCECodes{
		CodeChallenge: "challenge-value",
	})
	if err != nil {
		t.Fatalf("GenerateAuthURL() error = %v", err)
	}
	if returnedState != "state-value" {
		t.Fatalf("returned state = %q", returnedState)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse(authURL) error = %v", err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != AuthURL {
		t.Fatalf("authorization endpoint = %q", got)
	}
	if got := parsed.Query().Get("code_challenge"); got != "challenge-value" {
		t.Fatalf("code_challenge = %q", got)
	}
	if got := parsed.Query().Get("scope"); got != OAuthScope {
		t.Fatalf("authorization scope = %q", got)
	}
}

func TestExchangeCodeForTokensUsesThirtySecondDeadline(t *testing.T) {
	var remaining time.Duration
	auth := &ClaudeAuth{
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			deadline, ok := req.Context().Deadline()
			if !ok {
				t.Fatal("token exchange request has no deadline")
			}
			remaining = time.Until(deadline)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{
					"access_token":"exchange-access",
					"refresh_token":"exchange-refresh",
					"expires_in":3600,
					"account":{"uuid":"11111111-1111-4111-8111-111111111111","email_address":"user@example.com"},
					"organization":{"uuid":"22222222-2222-4222-a222-222222222222"}
				}`)),
			}, nil
		})},
		tokenURL: "https://platform.claude.com/v1/oauth/token",
	}
	if _, err := auth.ExchangeCodeForTokens(context.Background(), "authorization-code", "state-value", &PKCECodes{CodeVerifier: "verifier"}); err != nil {
		t.Fatalf("ExchangeCodeForTokens() error = %v", err)
	}
	if remaining < 29*time.Second || remaining > claudeTokenExchangeTimeout {
		t.Fatalf("token exchange deadline remaining = %v, want approximately 30s", remaining)
	}
}

func TestExchangeCodeForTokensBackfillsSparseIdentityFromProfile(t *testing.T) {
	const accessToken = "exchange-access-token"
	const accountUUID = "11111111-1111-4111-8111-111111111111"
	const organizationUUID = "22222222-2222-4222-a222-222222222222"

	var tokenCalls int32
	var profileCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth/token":
			atomic.AddInt32(&tokenCalls, 1)
			if r.Method != http.MethodPost {
				t.Errorf("token method = %s", r.Method)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode token request: %v", err)
			}
			if got := body["grant_type"]; got != "authorization_code" {
				t.Errorf("grant_type = %#v", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"`+accessToken+`","refresh_token":"exchange-refresh","expires_in":3600}`)
		case "/api/oauth/profile":
			atomic.AddInt32(&profileCalls, 1)
			if r.Method != http.MethodGet {
				t.Errorf("profile method = %s", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer "+accessToken {
				t.Errorf("profile authorization = %q", got)
			}
			if got := r.Header.Get("Cache-Control"); got != "no-cache" {
				t.Errorf("profile Cache-Control = %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"account":{"uuid":"`+accountUUID+`","email":"exchange@example.com"},
				"organization":{"uuid":"`+organizationUUID+`"}
			}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	auth := &ClaudeAuth{
		httpClient: server.Client(),
		tokenURL:   server.URL + "/v1/oauth/token",
		apiBaseURL: server.URL + "/",
	}
	bundle, err := auth.ExchangeCodeForTokens(context.Background(), "authorization-code", "state-value", &PKCECodes{
		CodeVerifier: "verifier-value",
	})
	if err != nil {
		t.Fatalf("ExchangeCodeForTokens() error = %v", err)
	}
	if got := bundle.TokenData.AccountUUID; got != accountUUID {
		t.Fatalf("account UUID = %q", got)
	}
	if got := bundle.TokenData.Email; got != "exchange@example.com" {
		t.Fatalf("email = %q", got)
	}
	if got := bundle.TokenData.OrganizationUUID; got != organizationUUID {
		t.Fatalf("organization UUID = %q", got)
	}
	if got := atomic.LoadInt32(&tokenCalls); got != 1 {
		t.Fatalf("token calls = %d", got)
	}
	if got := atomic.LoadInt32(&profileCalls); got != 1 {
		t.Fatalf("profile calls = %d", got)
	}
}

func TestRefreshTokensBackfillsOnlyMissingIdentityFromProfile(t *testing.T) {
	resetClaudeRefreshState()
	defer resetClaudeRefreshState()

	const accessToken = "refresh-access-token"
	const tokenAccountUUID = "33333333-3333-4333-8333-333333333333"
	const profileAccountUUID = "44444444-4444-4444-8444-444444444444"
	const organizationUUID = "55555555-5555-4555-8555-555555555555"

	var profileCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth/token":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode refresh request: %v", err)
			}
			if got := body["grant_type"]; got != "refresh_token" {
				t.Errorf("refresh grant_type = %#v", got)
			}
			if got := body["scope"]; got != OAuthScope {
				t.Errorf("refresh scope = %#v", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"access_token":"`+accessToken+`",
				"expires_in":3600,
				"account":{"uuid":"`+tokenAccountUUID+`"}
			}`)
		case "/api/oauth/profile":
			atomic.AddInt32(&profileCalls, 1)
			if got := r.Header.Get("Authorization"); got != "Bearer "+accessToken {
				t.Errorf("profile authorization = %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"account":{"uuid":"`+profileAccountUUID+`","email":"refresh@example.com"},
				"organization":{"uuid":"`+organizationUUID+`"}
			}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	auth := &ClaudeAuth{
		httpClient: server.Client(),
		tokenURL:   server.URL + "/v1/oauth/token",
		apiBaseURL: server.URL,
	}
	tokenData, err := auth.RefreshTokens(context.Background(), "profile-refresh-token")
	if err != nil {
		t.Fatalf("RefreshTokens() error = %v", err)
	}
	if got := tokenData.AccountUUID; got != tokenAccountUUID {
		t.Fatalf("token-provided account UUID was overwritten: %q", got)
	}
	if got := tokenData.Email; got != "refresh@example.com" {
		t.Fatalf("email = %q", got)
	}
	if got := tokenData.OrganizationUUID; got != organizationUUID {
		t.Fatalf("organization UUID = %q", got)
	}
	if got := atomic.LoadInt32(&profileCalls); got != 1 {
		t.Fatalf("profile calls = %d", got)
	}
}

func TestSparseRefreshProfileFailurePreservesStoredIdentity(t *testing.T) {
	resetClaudeRefreshState()
	defer resetClaudeRefreshState()

	const accessToken = "sparse-access-token"
	var profileCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"`+accessToken+`","expires_in":3600}`)
		case "/api/oauth/profile":
			atomic.AddInt32(&profileCalls, 1)
			if got := r.Header.Get("Authorization"); got != "Bearer "+accessToken {
				t.Errorf("profile authorization = %q", got)
			}
			http.Error(w, "temporary outage", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	auth := &ClaudeAuth{
		httpClient: server.Client(),
		tokenURL:   server.URL + "/v1/oauth/token",
		apiBaseURL: server.URL,
	}
	tokenData, err := auth.RefreshTokens(context.Background(), "sparse-refresh-token")
	if err != nil {
		t.Fatalf("RefreshTokens() error = %v", err)
	}
	if tokenData.AccountUUID != "" || tokenData.Email != "" || tokenData.OrganizationUUID != "" {
		t.Fatalf("expected sparse refreshed identity, got %#v", tokenData)
	}

	storage := &ClaudeTokenStorage{
		AccessToken:      "old-access",
		RefreshToken:     "old-refresh",
		Email:            "stored@example.com",
		AccountUUID:      "66666666-6666-4666-8666-666666666666",
		OrganizationUUID: "77777777-7777-4777-8777-777777777777",
	}
	auth.UpdateTokenStorage(storage, tokenData)
	if storage.Email != "stored@example.com" ||
		storage.AccountUUID != "66666666-6666-4666-8666-666666666666" ||
		storage.OrganizationUUID != "77777777-7777-4777-8777-777777777777" {
		t.Fatalf("sparse refresh erased stored identity: %#v", storage)
	}
	if storage.RefreshToken != "old-refresh" {
		t.Fatalf("sparse refresh erased refresh token: %q", storage.RefreshToken)
	}
	if got := atomic.LoadInt32(&profileCalls); got != 1 {
		t.Fatalf("profile calls = %d", got)
	}
}

func TestCompleteTokenIdentitySkipsProfileLookup(t *testing.T) {
	var calls int32
	auth := &ClaudeAuth{
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&calls, 1)
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader("unexpected request")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})},
	}
	tokenResp := &tokenResponse{AccessToken: "complete-access-token"}
	tokenResp.Account.UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tokenResp.Account.EmailAddress = "complete@example.com"
	tokenResp.Organization.UUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	auth.backfillTokenIdentity(context.Background(), tokenResp)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("complete identity caused %d profile requests", got)
	}
}

func TestFetchOAuthProfileErrorDoesNotExposeTokenOrBody(t *testing.T) {
	const accessToken = "secret-access-token-must-not-leak"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream echoed "+accessToken, http.StatusUnauthorized)
	}))
	defer server.Close()

	auth := &ClaudeAuth{httpClient: server.Client(), apiBaseURL: server.URL}
	_, err := auth.fetchOAuthProfile(context.Background(), accessToken)
	if err == nil {
		t.Fatal("expected OAuth profile error")
	}
	if strings.Contains(err.Error(), accessToken) || strings.Contains(err.Error(), "upstream echoed") {
		t.Fatalf("profile error exposed credential or response body: %q", err)
	}
}

func TestRefreshTokensWithRetry_429BlocksImmediateReplay(t *testing.T) {
	resetClaudeRefreshState()
	defer resetClaudeRefreshState()

	var calls int32
	auth := &ClaudeAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				atomic.AddInt32(&calls, 1)
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Body:       io.NopCloser(strings.NewReader(`{"error":"rate_limited"}`)),
					Header:     http.Header{"Retry-After": []string{"60"}},
					Request:    req,
				}, nil
			}),
		},
	}

	_, err := auth.RefreshTokensWithRetry(context.Background(), "dummy_refresh_token", 3)
	if err == nil {
		t.Fatalf("expected 429 refresh error")
	}
	if !strings.Contains(err.Error(), "status 429") {
		t.Fatalf("expected status 429 in error, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 refresh attempt after 429, got %d", got)
	}

	_, err = auth.RefreshTokensWithRetry(context.Background(), "dummy_refresh_token", 3)
	if err == nil {
		t.Fatalf("expected immediate blocked refresh error")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected blocked retry to avoid a second refresh call, got %d attempts", got)
	}
	if blockedUntil := claudeRefreshBlockedUntil("dummy_refresh_token"); !blockedUntil.After(time.Now()) {
		t.Fatalf("expected blocked-until timestamp to be set, got %v", blockedUntil)
	}
}

func TestRefreshTokens_DeduplicatesConcurrentRefresh(t *testing.T) {
	resetClaudeRefreshState()
	defer resetClaudeRefreshState()

	var calls int32
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	auth := &ClaudeAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				atomic.AddInt32(&calls, 1)
				once.Do(func() { close(started) })
				<-release
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"access_token":"new-access",
						"refresh_token":"new-refresh",
						"token_type":"Bearer",
						"expires_in":3600,
						"account":{"uuid":"88888888-8888-4888-8888-888888888888","email_address":"shared@example.com"},
						"organization":{"uuid":"99999999-9999-4999-8999-999999999999"}
					}`)),
					Header:  make(http.Header),
					Request: req,
				}, nil
			}),
		},
	}

	results := make(chan *ClaudeTokenData, 2)
	errs := make(chan error, 2)
	runRefresh := func() {
		td, err := auth.RefreshTokens(context.Background(), "shared-refresh-token")
		results <- td
		errs <- err
	}

	go runRefresh()
	go runRefresh()

	<-started
	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected concurrent refresh to share a single upstream call, got %d", got)
	}
	close(release)

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("expected refresh to succeed, got %v", err)
		}
		td := <-results
		if td == nil || td.AccessToken != "new-access" {
			t.Fatalf("expected refreshed access token, got %#v", td)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 upstream refresh call, got %d", got)
	}
}

func TestRefreshTokensAppliesThirtySecondRequestDeadline(t *testing.T) {
	resetClaudeRefreshState()
	defer resetClaudeRefreshState()

	deadlineRemaining := make(chan time.Duration, 1)
	auth := &ClaudeAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				deadline, ok := req.Context().Deadline()
				if !ok {
					deadlineRemaining <- 0
				} else {
					deadlineRemaining <- time.Until(deadline)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"access_token":"deadline-access",
						"refresh_token":"deadline-refresh",
						"expires_in":3600,
						"account":{"uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","email_address":"deadline@example.com"},
						"organization":{"uuid":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
					}`)),
					Header:  make(http.Header),
					Request: req,
				}, nil
			}),
		},
	}

	if _, err := auth.RefreshTokens(context.Background(), "deadline-refresh-token"); err != nil {
		t.Fatalf("RefreshTokens() error = %v", err)
	}
	remaining := <-deadlineRemaining
	if remaining < 29*time.Second || remaining > claudeRefreshTimeout {
		t.Fatalf("refresh request deadline remaining = %s, want approximately %s", remaining, claudeRefreshTimeout)
	}
}

func TestRefreshAndStoragePreserveClaudeOAuthIdentity(t *testing.T) {
	resetClaudeRefreshState()
	defer resetClaudeRefreshState()

	const accountUUID = "11111111-1111-4111-8111-111111111111"
	const organizationUUID = "22222222-2222-4222-a222-222222222222"
	auth := &ClaudeAuth{
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"access_token":"new-access",
						"refresh_token":"new-refresh",
						"expires_in":3600,
						"account":{"uuid":"` + accountUUID + `","email_address":"user@example.com"},
						"organization":{"uuid":"` + organizationUUID + `","name":"Example"}
					}`)),
					Header:  make(http.Header),
					Request: req,
				}, nil
			}),
		},
	}

	tokenData, errRefresh := auth.RefreshTokens(context.Background(), "identity-refresh-token")
	if errRefresh != nil {
		t.Fatalf("RefreshTokens() error = %v", errRefresh)
	}
	if tokenData.AccountUUID != accountUUID || tokenData.OrganizationUUID != organizationUUID {
		t.Fatalf("refreshed identity = account %q organization %q", tokenData.AccountUUID, tokenData.OrganizationUUID)
	}

	bundle := &ClaudeAuthBundle{TokenData: *tokenData, LastRefresh: "2026-07-20T00:00:00Z"}
	storage := auth.CreateTokenStorage(bundle)
	if storage.AccountUUID != accountUUID || storage.OrganizationUUID != organizationUUID {
		t.Fatalf("stored identity = account %q organization %q", storage.AccountUUID, storage.OrganizationUUID)
	}

	auth.UpdateTokenStorage(storage, &ClaudeTokenData{AccessToken: "rotated", Expire: "later"})
	if storage.AccountUUID != accountUUID || storage.OrganizationUUID != organizationUUID {
		t.Fatalf("identity was erased by sparse refresh: %#v", storage)
	}
}
