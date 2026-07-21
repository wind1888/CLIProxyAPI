package claude

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
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
	if RedirectURI != "https://platform.claude.com/oauth/code/callback" {
		t.Fatalf("RedirectURI = %q", RedirectURI)
	}
	if OAuthAuthorizeScope != "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload" {
		t.Fatalf("OAuthAuthorizeScope = %q", OAuthAuthorizeScope)
	}
	if OAuthRefreshScope != "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload" {
		t.Fatalf("OAuthRefreshScope = %q", OAuthRefreshScope)
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
	if got := parsed.Query().Get("scope"); got != OAuthAuthorizeScope {
		t.Fatalf("authorization scope = %q", got)
	}
	if got := parsed.Query().Get("redirect_uri"); got != RedirectURI {
		t.Fatalf("authorization redirect_uri = %q", got)
	}
	if got := parsed.Query().Get("code"); got != "true" {
		t.Fatalf("authorization code flag = %q", got)
	}
	wantRawQuery := "code=true&client_id=" + ClientID +
		"&response_type=code&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback" +
		"&scope=org%3Acreate_api_key+user%3Aprofile+user%3Ainference+user%3Asessions%3Aclaude_code+user%3Amcp_servers+user%3Afile_upload" +
		"&code_challenge=challenge-value&code_challenge_method=S256&state=state-value"
	if parsed.RawQuery != wantRawQuery {
		t.Fatalf("authorization query order differs\ngot:  %s\nwant: %s", parsed.RawQuery, wantRawQuery)
	}
}

func TestReadClaudeOAuthResponseDecodesAdvertisedEncodings(t *testing.T) {
	const payload = `{"access_token":"compressed-token","expires_in":3600}`
	encoders := map[string]func(*bytes.Buffer) io.WriteCloser{
		"gzip": func(buffer *bytes.Buffer) io.WriteCloser { return gzip.NewWriter(buffer) },
		"br":   func(buffer *bytes.Buffer) io.WriteCloser { return brotli.NewWriter(buffer) },
	}
	for encoding, newWriter := range encoders {
		t.Run(encoding, func(t *testing.T) {
			var compressed bytes.Buffer
			writer := newWriter(&compressed)
			if _, err := writer.Write([]byte(payload)); err != nil {
				t.Fatalf("compress payload: %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("close compressor: %v", err)
			}
			resp := &http.Response{
				Body:   io.NopCloser(bytes.NewReader(compressed.Bytes())),
				Header: http.Header{"Content-Encoding": {encoding}},
			}
			got, err := readClaudeOAuthResponse(resp)
			if err != nil {
				t.Fatalf("readClaudeOAuthResponse() error = %v", err)
			}
			if string(got) != payload {
				t.Fatalf("decoded payload = %q, want %q", got, payload)
			}
		})
	}
}

func TestClaudeOAuthRandomValuesMatchClaudeCode(t *testing.T) {
	pkce, errPKCE := GeneratePKCECodes()
	if errPKCE != nil {
		t.Fatalf("GeneratePKCECodes() error = %v", errPKCE)
	}
	state, errState := GenerateOAuthState()
	if errState != nil {
		t.Fatalf("GenerateOAuthState() error = %v", errState)
	}
	for name, value := range map[string]string{"code verifier": pkce.CodeVerifier, "state": state} {
		if len(value) != 43 {
			t.Fatalf("%s length = %d, want 43", name, len(value))
		}
		decoded, errDecode := base64.RawURLEncoding.DecodeString(value)
		if errDecode != nil {
			t.Fatalf("decode %s: %v", name, errDecode)
		}
		if len(decoded) != 32 {
			t.Fatalf("decoded %s bytes = %d, want 32", name, len(decoded))
		}
	}
	wantChallenge := sha256.Sum256([]byte(pkce.CodeVerifier))
	if got, want := pkce.CodeChallenge, base64.RawURLEncoding.EncodeToString(wantChallenge[:]); got != want {
		t.Fatalf("code challenge = %q, want %q", got, want)
	}
}

func TestRefreshTokenExpiryMatchesClaudeCodeMissingValueBehavior(t *testing.T) {
	before := time.Now().Add(30 * 24 * time.Hour).UnixMilli()
	loginExpiry := claudeRefreshTokenExpiresAt(nil, true)
	after := time.Now().Add(30 * 24 * time.Hour).UnixMilli()
	if loginExpiry < before || loginExpiry > after {
		t.Fatalf("missing login refresh expiry = %d, want [%d,%d]", loginExpiry, before, after)
	}
	if got := claudeRefreshTokenExpiresAt(nil, false); got != 0 {
		t.Fatalf("missing refresh-time expiry = %d, want preserve-existing sentinel 0", got)
	}
	zero := int64(0)
	beforeZero := time.Now().UnixMilli()
	zeroExpiry := claudeRefreshTokenExpiresAt(&zero, true)
	afterZero := time.Now().UnixMilli()
	if zeroExpiry < beforeZero || zeroExpiry > afterZero {
		t.Fatalf("explicit zero expiry = %d, want current time [%d,%d]", zeroExpiry, beforeZero, afterZero)
	}
}

func TestExchangeCodeForTokensUsesThirtySecondDeadline(t *testing.T) {
	var remaining time.Duration
	auth := &ClaudeAuth{
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodGet {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"account":{},"organization":{}}`)),
				}, nil
			}
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

func TestClaudeTokenResponsesMatchOfficialPermissiveParsing(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "missing access token", body: `{"expires_in":3600}`},
		{name: "blank access token", body: `{"access_token":"   ","expires_in":3600}`},
		{name: "missing expiry", body: `{"access_token":"token"}`},
		{name: "negative expiry", body: `{"access_token":"token","expires_in":-1}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &ClaudeAuth{httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(strings.NewReader(test.body)),
					Request:    req,
				}, nil
			})}}
			if _, err := auth.ExchangeCodeForTokens(context.Background(), "authorization-code", "state", &PKCECodes{CodeVerifier: "verifier"}); err != nil {
				t.Fatalf("ExchangeCodeForTokens() error = %v", err)
			}
		})
	}
}

func TestTokenEndpointErrorDoesNotExposeResponseBody(t *testing.T) {
	const secret = "secret-refresh-token-must-not-leak"
	auth := &ClaudeAuth{httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"error":"` + secret + `"}`)),
			Request:    req,
		}, nil
	})}}
	_, err := auth.ExchangeCodeForTokens(context.Background(), "authorization-code", "state", &PKCECodes{CodeVerifier: "verifier"})
	if err == nil {
		t.Fatal("ExchangeCodeForTokens() error = nil")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("token endpoint error exposed response body: %q", err)
	}
}

func TestExchangeCodeForTokensBackfillsSparseIdentityFromProfile(t *testing.T) {
	const accessToken = "exchange-access-token"
	const accountUUID = "11111111-1111-4111-8111-111111111111"
	const organizationUUID = "22222222-2222-4222-a222-222222222222"

	var tokenCalls int32
	var profileCalls int32
	var tokenRequestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth/token":
			atomic.AddInt32(&tokenCalls, 1)
			if r.Method != http.MethodPost {
				t.Errorf("token method = %s", r.Method)
			}
			rawBody, errRead := io.ReadAll(r.Body)
			if errRead != nil {
				t.Errorf("read token request: %v", errRead)
			}
			tokenRequestBody = string(rawBody)
			if got := r.Header.Get("User-Agent"); got != claudeOAuthUserAgent {
				t.Errorf("exchange User-Agent = %q", got)
			}
			if got := r.Header.Get("Accept-Encoding"); got != claudeOAuthAcceptEncoding {
				t.Errorf("exchange Accept-Encoding = %q", got)
			}
			var body map[string]any
			if err := json.Unmarshal(rawBody, &body); err != nil {
				t.Errorf("decode token request: %v", err)
			}
			if got := body["grant_type"]; got != "authorization_code" {
				t.Errorf("grant_type = %#v", got)
			}
			if got := body["redirect_uri"]; got != "http://localhost:43123/callback" {
				t.Errorf("redirect_uri = %#v", got)
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
			if got := r.Header.Get("Accept"); got != claudeOAuthAccept {
				t.Errorf("profile Accept = %q", got)
			}
			if got := r.Header.Get("User-Agent"); got != claudeOAuthUserAgent {
				t.Errorf("profile User-Agent = %q", got)
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
	bundle, err := auth.ExchangeCodeForTokensWithRedirectURI(context.Background(), "authorization-code#pasted-state", "state-value", &PKCECodes{
		CodeVerifier: "verifier-value",
	}, "http://localhost:43123/callback")
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
	wantTokenRequestBody := `{"grant_type":"authorization_code","code":"authorization-code","redirect_uri":"http://localhost:43123/callback","client_id":"` + ClientID + `","code_verifier":"verifier-value","state":"state-value"}`
	if tokenRequestBody != wantTokenRequestBody {
		t.Fatalf("token request body order differs\ngot:  %s\nwant: %s", tokenRequestBody, wantTokenRequestBody)
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
	var refreshRequestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth/token":
			rawBody, _ := io.ReadAll(r.Body)
			refreshRequestBody = string(rawBody)
			var body map[string]any
			if err := json.Unmarshal(rawBody, &body); err != nil {
				t.Errorf("decode refresh request: %v", err)
			}
			if got := body["grant_type"]; got != "refresh_token" {
				t.Errorf("refresh grant_type = %#v", got)
			}
			if got := body["scope"]; got != OAuthScope {
				t.Errorf("refresh scope = %#v", got)
			}
			if got := r.Header.Get("User-Agent"); got != claudeOAuthUserAgent {
				t.Errorf("refresh User-Agent = %q", got)
			}
			if got := r.Header.Get("Accept-Encoding"); got != claudeOAuthAcceptEncoding {
				t.Errorf("refresh Accept-Encoding = %q", got)
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
	if got, want := tokenData.RefreshToken, "profile-refresh-token"; got != want {
		t.Fatalf("refresh token = %q, want preserved %q", got, want)
	}
	wantRefreshBody := `{"grant_type":"refresh_token","refresh_token":"profile-refresh-token","client_id":"` + ClientID + `","scope":"` + OAuthRefreshScope + `"}`
	if refreshRequestBody != wantRefreshBody {
		t.Fatalf("refresh request body order differs\ngot:  %s\nwant: %s", refreshRequestBody, wantRefreshBody)
	}
	if got := atomic.LoadInt32(&profileCalls); got != 1 {
		t.Fatalf("profile calls = %d", got)
	}
}

func TestRefreshTokensRetriesStoredScopesAfterOfficialInvalidScope(t *testing.T) {
	resetClaudeRefreshState()
	defer resetClaudeRefreshState()

	storedScopes := []string{
		"org:create_api_key",
		"user:inference",
		"user:projects:write",
		"legacy:scope",
	}
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(rawBody))
		w.Header().Set("Content-Type", "application/json")
		if len(bodies) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"type":"invalid_scope"}}`)
			return
		}
		_, _ = io.WriteString(w, `{
			"access_token":"new-access",
			"expires_in":3600,
			"scope":"user:profile user:inference",
			"account":{"uuid":"11111111-1111-4111-8111-111111111111","email_address":"user@example.com"},
			"organization":{"uuid":"22222222-2222-4222-a222-222222222222"}
		}`)
	}))
	defer server.Close()

	auth := &ClaudeAuth{httpClient: server.Client(), tokenURL: server.URL}
	tokenData, err := auth.RefreshTokensWithScopes(context.Background(), "old-refresh", storedScopes, "", "")
	if err != nil {
		t.Fatalf("RefreshTokensWithScopes() error = %v", err)
	}
	if got, want := tokenData.RefreshToken, "old-refresh"; got != want {
		t.Fatalf("refresh token = %q, want %q", got, want)
	}
	if len(bodies) != 2 {
		t.Fatalf("refresh requests = %d, want 2", len(bodies))
	}
	firstScope := OAuthRefreshScope + " user:projects:write"
	wantFirst := `{"grant_type":"refresh_token","refresh_token":"old-refresh","client_id":"` + ClientID + `","scope":"` + firstScope + `"}`
	wantSecond := `{"grant_type":"refresh_token","refresh_token":"old-refresh","client_id":"` + ClientID + `","scope":"` + strings.Join(storedScopes, " ") + `"}`
	if bodies[0] != wantFirst || bodies[1] != wantSecond {
		t.Fatalf("refresh scope retry differs\nfirst:  %s\nwant:   %s\nsecond: %s\nwant:   %s", bodies[0], wantFirst, bodies[1], wantSecond)
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
		RefreshToken:     "sparse-refresh-token",
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
	if storage.RefreshToken != "sparse-refresh-token" {
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

	auth.backfillTokenIdentity(context.Background(), tokenResp, false)
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

func TestRefreshTokensWithScopesAndRetryCapturesOfficialRotationMetadata(t *testing.T) {
	resetClaudeRefreshState()
	defer resetClaudeRefreshState()

	var profileCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/oauth/token":
			_, _ = io.WriteString(w, `{
				"access_token":"rotated-access","refresh_token":"rotated-refresh",
				"expires_in":3600,"refresh_token_expires_in":86400,
				"scope":"user:profile user:inference",
				"account":{"uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","email_address":"user@example.com"},
				"organization":{"uuid":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
			}`)
		case "/api/oauth/profile":
			atomic.AddInt32(&profileCalls, 1)
			_, _ = io.WriteString(w, `{
				"account":{"uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","email":"user@example.com"},
				"organization":{"uuid":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","organization_type":"claude_max","rate_limit_tier":"default_claude_max_20x"}
			}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	auth := &ClaudeAuth{httpClient: server.Client(), tokenURL: server.URL + "/v1/oauth/token", apiBaseURL: server.URL}
	before := time.Now().UnixMilli() + 86400*1000
	tokenData, err := auth.RefreshTokensWithScopesAndRetry(context.Background(), "old-refresh", []string{"user:inference"}, "", "", "", 1)
	if err != nil {
		t.Fatalf("RefreshTokensWithScopesAndRetry() error = %v", err)
	}
	after := time.Now().UnixMilli() + 86400*1000
	if tokenData.RefreshTokenExpiresAt < before || tokenData.RefreshTokenExpiresAt > after {
		t.Fatalf("refreshTokenExpiresAt = %d, want [%d,%d]", tokenData.RefreshTokenExpiresAt, before, after)
	}
	if tokenData.SubscriptionType != "max" || tokenData.RateLimitTier != "default_claude_max_20x" {
		t.Fatalf("profile metadata = subscription %q tier %q", tokenData.SubscriptionType, tokenData.RateLimitTier)
	}
	if tokenData.ClientID != "" {
		t.Fatalf("default first-party client ID should remain implicit, got %q", tokenData.ClientID)
	}
	if got := atomic.LoadInt32(&profileCalls); got != 1 {
		t.Fatalf("profile calls = %d, want 1", got)
	}
}

func TestInvalidGrantIsPermanentUnauthorizedRefreshFailure(t *testing.T) {
	resetClaudeRefreshState()
	defer resetClaudeRefreshState()
	auth := &ClaudeAuth{httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_grant"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}}

	_, err := auth.RefreshTokensWithRetry(context.Background(), "dead-refresh", 3)
	if err == nil || !IsInvalidGrantError(err) {
		t.Fatalf("invalid_grant error not preserved: %v", err)
	}
	var statusCoder interface{ StatusCode() int }
	if !errors.As(err, &statusCoder) || statusCoder.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("invalid_grant status = %#v, want 401", statusCoder)
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
