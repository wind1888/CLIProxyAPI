// Package claude provides OAuth2 authentication functionality for Anthropic's Claude API.
// This package implements the complete OAuth2 flow with PKCE (Proof Key for Code Exchange)
// for secure authentication with Claude API, including token exchange, refresh, and storage.
package claude

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

// OAuth configuration constants for Claude/Anthropic
const (
	AuthURL     = "https://claude.com/cai/oauth/authorize"
	TokenURL    = "https://platform.claude.com/v1/oauth/token"
	APIBaseURL  = "https://api.anthropic.com"
	ClientID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	RedirectURI = "http://localhost:54545/callback"
	OAuthScope  = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"

	claudeRefreshMinBackoff    = 5 * time.Second
	claudeRefreshMaxBackoff    = 5 * time.Minute
	claudeTokenExchangeTimeout = 30 * time.Second
	claudeRefreshTimeout       = 30 * time.Second
	claudeProfileTimeout       = 10 * time.Second
)

var (
	claudeRefreshGroup singleflight.Group
	claudeRefreshMu    sync.Mutex
	claudeRefreshBlock = make(map[string]time.Time)
)

type refreshHTTPError struct {
	status    int
	message   string
	retryable bool
}

func (e *refreshHTTPError) Error() string {
	return fmt.Sprintf("token refresh failed with status %d: %s", e.status, e.message)
}

func (e *refreshHTTPError) Retryable() bool {
	return e != nil && e.retryable
}

func resetClaudeRefreshState() {
	claudeRefreshMu.Lock()
	defer claudeRefreshMu.Unlock()
	claudeRefreshBlock = make(map[string]time.Time)
	claudeRefreshGroup = singleflight.Group{}
}

func claudeRefreshBlockedUntil(refreshToken string) time.Time {
	claudeRefreshMu.Lock()
	defer claudeRefreshMu.Unlock()
	return claudeRefreshBlock[refreshToken]
}

func setClaudeRefreshBlockedUntil(refreshToken string, until time.Time) {
	claudeRefreshMu.Lock()
	defer claudeRefreshMu.Unlock()
	claudeRefreshBlock[refreshToken] = until
}

func clearClaudeRefreshBlockedUntil(refreshToken string) {
	claudeRefreshMu.Lock()
	defer claudeRefreshMu.Unlock()
	delete(claudeRefreshBlock, refreshToken)
}

func clampClaudeRefreshBackoff(d time.Duration) time.Duration {
	if d < claudeRefreshMinBackoff {
		return claudeRefreshMinBackoff
	}
	if d > claudeRefreshMaxBackoff {
		return claudeRefreshMaxBackoff
	}
	return d
}

func parseClaudeRetryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return claudeRefreshMinBackoff
	}
	if raw := strings.TrimSpace(resp.Header.Get("Retry-After")); raw != "" {
		if seconds, err := time.ParseDuration(raw + "s"); err == nil {
			return clampClaudeRefreshBackoff(seconds)
		}
		if when, err := http.ParseTime(raw); err == nil {
			return clampClaudeRefreshBackoff(time.Until(when))
		}
	}
	if raw := strings.TrimSpace(resp.Header.Get("Retry-After-Ms")); raw != "" {
		if ms, err := time.ParseDuration(raw + "ms"); err == nil {
			return clampClaudeRefreshBackoff(ms)
		}
	}
	return claudeRefreshMinBackoff
}

func isClaudeRefreshRetryable(err error) bool {
	var httpErr *refreshHTTPError
	if errors.As(err, &httpErr) {
		return httpErr.Retryable()
	}
	return true
}

// tokenResponse represents the response structure from Anthropic's OAuth token endpoint.
// It contains access token, refresh token, and associated user/organization information.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Organization struct {
		UUID string `json:"uuid"`
		Name string `json:"name"`
	} `json:"organization"`
	Account struct {
		UUID         string `json:"uuid"`
		EmailAddress string `json:"email_address"`
	} `json:"account"`
}

// oauthProfileResponse is the identity subset returned by /api/oauth/profile.
// Unlike the token endpoint, the profile endpoint names the account email field
// "email". EmailAddress is retained as a defensive compatibility fallback.
type oauthProfileResponse struct {
	Account struct {
		UUID         string `json:"uuid"`
		Email        string `json:"email"`
		EmailAddress string `json:"email_address"`
	} `json:"account"`
	Organization struct {
		UUID string `json:"uuid"`
	} `json:"organization"`
}

// ClaudeAuth handles Anthropic OAuth2 authentication flow.
// It provides methods for generating authorization URLs, exchanging codes for tokens,
// and refreshing expired tokens using PKCE for enhanced security.
type ClaudeAuth struct {
	httpClient *http.Client
	tokenURL   string
	apiBaseURL string
}

// NewClaudeAuth creates a new Anthropic authentication service.
// It initializes the HTTP client with a custom TLS transport that uses Firefox
// fingerprint to bypass Cloudflare's TLS fingerprinting on Anthropic domains.
//
// Parameters:
//   - cfg: The application configuration containing proxy settings
//
// Returns:
//   - *ClaudeAuth: A new Claude authentication service instance
func NewClaudeAuth(cfg *config.Config) *ClaudeAuth {
	return NewClaudeAuthWithProxyURL(cfg, "")
}

// NewClaudeAuthWithProxyURL creates a new Anthropic authentication service with a proxy override.
// proxyURL takes precedence over cfg.ProxyURL when non-empty.
func NewClaudeAuthWithProxyURL(cfg *config.Config, proxyURL string) *ClaudeAuth {
	effectiveProxyURL := strings.TrimSpace(proxyURL)
	var sdkCfg *config.SDKConfig
	if cfg != nil {
		sdkCfgCopy := cfg.SDKConfig
		if effectiveProxyURL == "" {
			effectiveProxyURL = strings.TrimSpace(cfg.ProxyURL)
		}
		sdkCfgCopy.ProxyURL = effectiveProxyURL
		sdkCfg = &sdkCfgCopy
	} else if effectiveProxyURL != "" {
		sdkCfgCopy := config.SDKConfig{ProxyURL: effectiveProxyURL}
		sdkCfg = &sdkCfgCopy
	}

	// Use custom HTTP client with Firefox TLS fingerprint to bypass
	// Cloudflare's bot detection on Anthropic domains
	return &ClaudeAuth{
		httpClient: NewAnthropicHttpClient(sdkCfg),
		tokenURL:   TokenURL,
		apiBaseURL: APIBaseURL,
	}
}

func (o *ClaudeAuth) resolvedTokenURL() string {
	if o != nil {
		if endpoint := strings.TrimSpace(o.tokenURL); endpoint != "" {
			return endpoint
		}
	}
	return TokenURL
}

func (o *ClaudeAuth) resolvedOAuthProfileURL() string {
	baseURL := ""
	if o != nil {
		baseURL = strings.TrimSpace(o.apiBaseURL)
	}
	if baseURL == "" {
		baseURL = APIBaseURL
	}
	return strings.TrimRight(baseURL, "/") + "/api/oauth/profile"
}

func tokenResponseNeedsProfile(tokenResp *tokenResponse) bool {
	if tokenResp == nil {
		return false
	}
	return strings.TrimSpace(tokenResp.Account.UUID) == "" ||
		strings.TrimSpace(tokenResp.Account.EmailAddress) == "" ||
		strings.TrimSpace(tokenResp.Organization.UUID) == ""
}

// backfillTokenIdentity supplements sparse token responses with the first-party
// OAuth profile. Profile lookup is best-effort, matching Claude Code: a transient
// profile failure must not discard an otherwise valid access token.
func (o *ClaudeAuth) backfillTokenIdentity(ctx context.Context, tokenResp *tokenResponse) {
	if !tokenResponseNeedsProfile(tokenResp) || strings.TrimSpace(tokenResp.AccessToken) == "" {
		return
	}

	profile, err := o.fetchOAuthProfile(ctx, tokenResp.AccessToken)
	if err != nil {
		// fetchOAuthProfile deliberately returns sanitized errors that contain no
		// credential or response body.
		log.Warnf("Claude OAuth profile backfill failed: %v", err)
		return
	}

	if strings.TrimSpace(tokenResp.Account.UUID) == "" {
		tokenResp.Account.UUID = strings.TrimSpace(profile.Account.UUID)
	}
	if strings.TrimSpace(tokenResp.Account.EmailAddress) == "" {
		tokenResp.Account.EmailAddress = strings.TrimSpace(profile.Account.Email)
		if tokenResp.Account.EmailAddress == "" {
			tokenResp.Account.EmailAddress = strings.TrimSpace(profile.Account.EmailAddress)
		}
	}
	if strings.TrimSpace(tokenResp.Organization.UUID) == "" {
		tokenResp.Organization.UUID = strings.TrimSpace(profile.Organization.UUID)
	}
}

func (o *ClaudeAuth) fetchOAuthProfile(ctx context.Context, accessToken string) (*oauthProfileResponse, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("OAuth profile request skipped: access token is empty")
	}

	profileCtx, cancel := context.WithTimeout(ctx, claudeProfileTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(profileCtx, http.MethodGet, o.resolvedOAuthProfileURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth profile request")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OAuth profile request failed")
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OAuth profile request failed with status %d", resp.StatusCode)
	}

	var profile oauthProfileResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err = decoder.Decode(&profile); err != nil {
		return nil, fmt.Errorf("failed to parse OAuth profile response")
	}
	return &profile, nil
}

// GenerateAuthURL creates the OAuth authorization URL with PKCE.
// This method generates a secure authorization URL including PKCE challenge codes
// for the OAuth2 flow with Anthropic's API.
//
// Parameters:
//   - state: A random state parameter for CSRF protection
//   - pkceCodes: The PKCE codes for secure code exchange
//
// Returns:
//   - string: The complete authorization URL
//   - string: The state parameter for verification
//   - error: An error if PKCE codes are missing or URL generation fails
func (o *ClaudeAuth) GenerateAuthURL(state string, pkceCodes *PKCECodes) (string, string, error) {
	if pkceCodes == nil {
		return "", "", fmt.Errorf("PKCE codes are required")
	}

	params := url.Values{
		"code":                  {"true"},
		"client_id":             {ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {RedirectURI},
		"scope":                 {OAuthScope},
		"code_challenge":        {pkceCodes.CodeChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}

	authURL := fmt.Sprintf("%s?%s", AuthURL, params.Encode())
	return authURL, state, nil
}

// parseCodeAndState extracts the authorization code and state from the callback response.
// It handles the parsing of the code parameter which may contain additional fragments.
//
// Parameters:
//   - code: The raw code parameter from the OAuth callback
//
// Returns:
//   - parsedCode: The extracted authorization code
//   - parsedState: The extracted state parameter if present
func (c *ClaudeAuth) parseCodeAndState(code string) (parsedCode, parsedState string) {
	splits := strings.Split(code, "#")
	parsedCode = splits[0]
	if len(splits) > 1 {
		parsedState = splits[1]
	}
	return
}

// ExchangeCodeForTokens exchanges authorization code for access tokens.
// This method implements the OAuth2 token exchange flow using PKCE for security.
// It sends the authorization code along with PKCE verifier to get access and refresh tokens.
//
// Parameters:
//   - ctx: The context for the request
//   - code: The authorization code received from OAuth callback
//   - state: The state parameter for verification
//   - pkceCodes: The PKCE codes for secure verification
//
// Returns:
//   - *ClaudeAuthBundle: The complete authentication bundle with tokens
//   - error: An error if token exchange fails
func (o *ClaudeAuth) ExchangeCodeForTokens(ctx context.Context, code, state string, pkceCodes *PKCECodes) (*ClaudeAuthBundle, error) {
	if pkceCodes == nil {
		return nil, fmt.Errorf("PKCE codes are required for token exchange")
	}
	newCode, newState := o.parseCodeAndState(code)

	// Prepare token exchange request
	reqBody := map[string]interface{}{
		"code":          newCode,
		"state":         state,
		"grant_type":    "authorization_code",
		"client_id":     ClientID,
		"redirect_uri":  RedirectURI,
		"code_verifier": pkceCodes.CodeVerifier,
	}

	// Include state if present
	if newState != "" {
		reqBody["state"] = newState
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// log.Debugf("Token exchange request: %s", string(jsonBody))

	exchangeCtx, cancelExchange := context.WithTimeout(ctx, claudeTokenExchangeTimeout)
	defer cancelExchange()
	req, err := http.NewRequestWithContext(exchangeCtx, http.MethodPost, o.resolvedTokenURL(), strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("failed to close response body: %v", errClose)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}
	// log.Debugf("Token response: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}
	// log.Debugf("Token response: %s", string(body))

	var tokenResp tokenResponse
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	o.backfillTokenIdentity(ctx, &tokenResp)

	// Create token data
	tokenData := ClaudeTokenData{
		AccessToken:      tokenResp.AccessToken,
		RefreshToken:     tokenResp.RefreshToken,
		Email:            tokenResp.Account.EmailAddress,
		AccountUUID:      tokenResp.Account.UUID,
		OrganizationUUID: tokenResp.Organization.UUID,
		Expire:           time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
	}

	// Create auth bundle
	bundle := &ClaudeAuthBundle{
		TokenData:   tokenData,
		LastRefresh: time.Now().Format(time.RFC3339),
	}

	return bundle, nil
}

// RefreshTokens refreshes the access token using the refresh token.
// This method exchanges a valid refresh token for a new access token,
// extending the user's authenticated session.
//
// Parameters:
//   - ctx: The context for the request
//   - refreshToken: The refresh token to use for getting new access token
//
// Returns:
//   - *ClaudeTokenData: The new token data with updated access token
//   - error: An error if token refresh fails
func (o *ClaudeAuth) RefreshTokens(ctx context.Context, refreshToken string) (*ClaudeTokenData, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}
	if blockedUntil := claudeRefreshBlockedUntil(refreshToken); blockedUntil.After(time.Now()) {
		return nil, &refreshHTTPError{
			status:    http.StatusTooManyRequests,
			message:   fmt.Sprintf("refresh temporarily blocked until %s", blockedUntil.Format(time.RFC3339)),
			retryable: false,
		}
	}

	result, err, _ := claudeRefreshGroup.Do(refreshToken, func() (interface{}, error) {
		return o.refreshTokensSingleFlight(context.WithoutCancel(ctx), refreshToken)
	})
	if err != nil {
		return nil, err
	}
	tokenData, ok := result.(*ClaudeTokenData)
	if !ok || tokenData == nil {
		return nil, fmt.Errorf("token refresh failed: invalid single-flight result")
	}
	return tokenData, nil
}

func (o *ClaudeAuth) refreshTokensSingleFlight(ctx context.Context, refreshToken string) (*ClaudeTokenData, error) {
	if blockedUntil := claudeRefreshBlockedUntil(refreshToken); blockedUntil.After(time.Now()) {
		return nil, &refreshHTTPError{
			status:    http.StatusTooManyRequests,
			message:   fmt.Sprintf("refresh temporarily blocked until %s", blockedUntil.Format(time.RFC3339)),
			retryable: false,
		}
	}

	reqBody := map[string]interface{}{
		"client_id":     ClientID,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"scope":         OAuthScope,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	refreshCtx, cancelRefresh := context.WithTimeout(ctx, claudeRefreshTimeout)
	defer cancelRefresh()
	req, err := http.NewRequestWithContext(refreshCtx, http.MethodPost, o.resolvedTokenURL(), strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token refresh request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	cancelRefresh()
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		message := string(body)
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := parseClaudeRetryAfter(resp)
			setClaudeRefreshBlockedUntil(refreshToken, time.Now().Add(retryAfter))
			return nil, &refreshHTTPError{status: resp.StatusCode, message: message, retryable: false}
		}
		return nil, &refreshHTTPError{
			status:    resp.StatusCode,
			message:   message,
			retryable: resp.StatusCode >= http.StatusInternalServerError,
		}
	}

	// log.Debugf("Token response: %s", string(body))

	var tokenResp tokenResponse
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	o.backfillTokenIdentity(ctx, &tokenResp)

	// Create token data
	clearClaudeRefreshBlockedUntil(refreshToken)

	return &ClaudeTokenData{
		AccessToken:      tokenResp.AccessToken,
		RefreshToken:     tokenResp.RefreshToken,
		Email:            tokenResp.Account.EmailAddress,
		AccountUUID:      tokenResp.Account.UUID,
		OrganizationUUID: tokenResp.Organization.UUID,
		Expire:           time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
	}, nil
}

// CreateTokenStorage creates a new ClaudeTokenStorage from auth bundle and user info.
// This method converts the authentication bundle into a token storage structure
// suitable for persistence and later use.
//
// Parameters:
//   - bundle: The authentication bundle containing token data
//
// Returns:
//   - *ClaudeTokenStorage: A new token storage instance
func (o *ClaudeAuth) CreateTokenStorage(bundle *ClaudeAuthBundle) *ClaudeTokenStorage {
	storage := &ClaudeTokenStorage{
		AccessToken:      bundle.TokenData.AccessToken,
		RefreshToken:     bundle.TokenData.RefreshToken,
		LastRefresh:      bundle.LastRefresh,
		Email:            bundle.TokenData.Email,
		AccountUUID:      bundle.TokenData.AccountUUID,
		OrganizationUUID: bundle.TokenData.OrganizationUUID,
		Expire:           bundle.TokenData.Expire,
	}

	return storage
}

// RefreshTokensWithRetry refreshes tokens with automatic retry logic.
// This method implements exponential backoff retry logic for token refresh operations,
// providing resilience against temporary network or service issues.
//
// Parameters:
//   - ctx: The context for the request
//   - refreshToken: The refresh token to use
//   - maxRetries: The maximum number of retry attempts
//
// Returns:
//   - *ClaudeTokenData: The refreshed token data
//   - error: An error if all retry attempts fail
func (o *ClaudeAuth) RefreshTokensWithRetry(ctx context.Context, refreshToken string, maxRetries int) (*ClaudeTokenData, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		tokenData, err := o.RefreshTokens(ctx, refreshToken)
		if err == nil {
			return tokenData, nil
		}

		lastErr = err
		log.Warnf("Token refresh attempt %d failed: %v", attempt+1, err)
		if !isClaudeRefreshRetryable(err) {
			break
		}
	}

	return nil, fmt.Errorf("token refresh failed after %d attempts: %w", maxRetries, lastErr)
}

// UpdateTokenStorage updates an existing token storage with new token data.
// This method refreshes the token storage with newly obtained access and refresh tokens,
// updating timestamps and expiration information.
//
// Parameters:
//   - storage: The existing token storage to update
//   - tokenData: The new token data to apply
func (o *ClaudeAuth) UpdateTokenStorage(storage *ClaudeTokenStorage, tokenData *ClaudeTokenData) {
	if storage == nil || tokenData == nil {
		return
	}
	storage.AccessToken = tokenData.AccessToken
	if tokenData.RefreshToken != "" {
		storage.RefreshToken = tokenData.RefreshToken
	}
	storage.LastRefresh = time.Now().Format(time.RFC3339)
	if tokenData.Email != "" {
		storage.Email = tokenData.Email
	}
	if tokenData.AccountUUID != "" {
		storage.AccountUUID = tokenData.AccountUUID
	}
	if tokenData.OrganizationUUID != "" {
		storage.OrganizationUUID = tokenData.OrganizationUUID
	}
	storage.Expire = tokenData.Expire
}
