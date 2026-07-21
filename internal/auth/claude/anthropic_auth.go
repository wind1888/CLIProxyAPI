// Package claude provides OAuth2 authentication functionality for Anthropic's Claude API.
// This package implements the complete OAuth2 flow with PKCE (Proof Key for Code Exchange)
// for secure authentication with Claude API, including token exchange, refresh, and storage.
package claude

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/lzw"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

// OAuth configuration constants for Claude/Anthropic
const (
	AuthURL            = "https://claude.com/cai/oauth/authorize"
	TokenURL           = "https://platform.claude.com/v1/oauth/token"
	APIBaseURL         = "https://api.anthropic.com"
	ClientID           = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	RedirectURI        = "https://platform.claude.com/oauth/code/callback"
	OAuthSuccessURL    = "https://platform.claude.com/oauth/code/success?app=claude-code"
	OAuthBuyCreditsURL = "https://platform.claude.com/buy_credits?returnUrl=/oauth/code/success%3Fapp%3Dclaude-code"

	OAuthAuthorizeScope       = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
	OAuthRefreshScope         = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
	OAuthScope                = OAuthRefreshScope
	claudeOAuthUserAgent      = "axios/1.15.2"
	claudeOAuthAccept         = "application/json, text/plain, */*"
	claudeOAuthAcceptEncoding = "gzip, compress, deflate, br"

	claudeRefreshMinBackoff    = 5 * time.Second
	claudeRefreshMaxBackoff    = 5 * time.Minute
	claudeTokenExchangeTimeout = 30 * time.Second
	claudeRefreshTimeout       = 30 * time.Second
	claudeProfileTimeout       = 10 * time.Second
	claudeOAuthResponseLimit   = 4 << 20
)

var (
	claudeRefreshGroup singleflight.Group
	claudeRefreshMu    sync.Mutex
	claudeRefreshBlock = make(map[string]time.Time)
)

type refreshHTTPError struct {
	status    int
	message   string
	oauthCode string
	retryable bool
}

func (e *refreshHTTPError) Error() string {
	return fmt.Sprintf("token refresh failed with status %d: %s", e.status, e.message)
}

func (e *refreshHTTPError) Retryable() bool {
	return e != nil && e.retryable
}

// StatusCode lets the auth manager distinguish a permanently dead rotating
// refresh token from a transient refresh failure. Claude Code treats
// invalid_grant as an unauthorized credential and stops retrying it.
func (e *refreshHTTPError) StatusCode() int {
	if e == nil {
		return 0
	}
	if strings.EqualFold(strings.TrimSpace(e.oauthCode), "invalid_grant") {
		return http.StatusUnauthorized
	}
	return e.status
}

// IsInvalidGrantError reports whether Anthropic rejected the current rotating
// refresh token. Wrapped retry errors remain detectable through errors.As.
func IsInvalidGrantError(err error) bool {
	var httpErr *refreshHTTPError
	return errors.As(err, &httpErr) && httpErr != nil &&
		strings.EqualFold(strings.TrimSpace(httpErr.oauthCode), "invalid_grant")
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
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshTokenExpiresIn *int64 `json:"refresh_token_expires_in"`
	Scope                 string `json:"scope"`
	Organization          struct {
		UUID             string `json:"uuid"`
		Name             string `json:"name"`
		OrganizationType string `json:"organization_type"`
		RateLimitTier    string `json:"rate_limit_tier"`
	} `json:"organization"`
	Account struct {
		UUID         string `json:"uuid"`
		EmailAddress string `json:"email_address"`
	} `json:"account"`
}

type tokenExchangeRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	CodeVerifier string `json:"code_verifier"`
	State        string `json:"state"`
}

type tokenRefreshRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
	Scope        string `json:"scope"`
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
		UUID             string `json:"uuid"`
		OrganizationType string `json:"organization_type"`
		RateLimitTier    string `json:"rate_limit_tier"`
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

func claudeSubscriptionType(organizationType string) string {
	switch strings.TrimSpace(organizationType) {
	case "claude_max":
		return "max"
	case "claude_pro":
		return "pro"
	case "claude_enterprise":
		return "enterprise"
	case "claude_team":
		return "team"
	default:
		return ""
	}
}

func claudeRefreshTokenExpiresAt(expiresIn *int64, defaultWhenMissing bool) int64 {
	if expiresIn != nil {
		return time.Now().UnixMilli() + *expiresIn*1000
	}
	if defaultWhenMissing {
		return time.Now().Add(30 * 24 * time.Hour).UnixMilli()
	}
	return 0
}

// backfillTokenIdentity supplements sparse token responses with the first-party
// OAuth profile. Profile lookup is best-effort, matching Claude Code: a transient
// profile failure must not discard an otherwise valid access token.
func (o *ClaudeAuth) backfillTokenIdentity(ctx context.Context, tokenResp *tokenResponse, alwaysFetch bool) {
	attempts := 1
	if alwaysFetch {
		attempts = 2
	}
	o.backfillTokenProfile(ctx, tokenResp, alwaysFetch, attempts)
}

func (o *ClaudeAuth) backfillTokenProfile(ctx context.Context, tokenResp *tokenResponse, force bool, attempts int) {
	if tokenResp == nil || strings.TrimSpace(tokenResp.AccessToken) == "" || (!force && !tokenResponseNeedsProfile(tokenResp)) {
		return
	}
	if attempts < 1 {
		attempts = 1
	}
	var profile *oauthProfileResponse
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		profile, err = o.fetchOAuthProfile(ctx, tokenResp.AccessToken)
		if err == nil {
			break
		}
	}
	if err != nil || profile == nil {
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
	if strings.TrimSpace(tokenResp.Organization.OrganizationType) == "" {
		tokenResp.Organization.OrganizationType = strings.TrimSpace(profile.Organization.OrganizationType)
	}
	if strings.TrimSpace(tokenResp.Organization.RateLimitTier) == "" {
		tokenResp.Organization.RateLimitTier = strings.TrimSpace(profile.Organization.RateLimitTier)
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
	req.Header.Set("Accept", claudeOAuthAccept)
	req.Header.Set("Accept-Encoding", claudeOAuthAcceptEncoding)
	req.Header.Set("User-Agent", claudeOAuthUserAgent)
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

	body, err := readClaudeOAuthResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read OAuth profile response")
	}
	var profile oauthProfileResponse
	if err = json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse OAuth profile response")
	}
	return &profile, nil
}

func readClaudeOAuthResponse(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("empty OAuth response")
	}
	body, err := readClaudeOAuthBytes(resp.Body)
	if err != nil || resp.Uncompressed {
		return body, err
	}
	encodings := strings.Split(resp.Header.Get("Content-Encoding"), ",")
	for index := len(encodings) - 1; index >= 0; index-- {
		encoding := strings.ToLower(strings.TrimSpace(strings.SplitN(encodings[index], ";", 2)[0]))
		if encoding == "" || encoding == "identity" {
			continue
		}
		body, err = decodeClaudeOAuthBytes(body, encoding)
		if err != nil {
			return nil, err
		}
	}
	return body, nil
}

func readClaudeOAuthBytes(reader io.Reader) ([]byte, error) {
	limited := io.LimitReader(reader, claudeOAuthResponseLimit+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > claudeOAuthResponseLimit {
		return nil, fmt.Errorf("OAuth response exceeds size limit")
	}
	return body, nil
}

func decodeClaudeOAuthBytes(body []byte, encoding string) ([]byte, error) {
	var reader io.Reader
	var closer io.Closer
	switch encoding {
	case "gzip", "x-gzip":
		gzipReader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		reader, closer = gzipReader, gzipReader
	case "br":
		reader = brotli.NewReader(bytes.NewReader(body))
	case "deflate":
		zlibReader, err := zlib.NewReader(bytes.NewReader(body))
		if err == nil {
			reader, closer = zlibReader, zlibReader
		} else {
			flateReader := flate.NewReader(bytes.NewReader(body))
			reader, closer = flateReader, flateReader
		}
	case "compress", "x-compress":
		lzwReader := lzw.NewReader(bytes.NewReader(body), lzw.MSB, 8)
		reader, closer = lzwReader, lzwReader
	default:
		return nil, fmt.Errorf("unsupported OAuth response encoding %q", encoding)
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	return readClaudeOAuthBytes(reader)
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
	return o.GenerateAuthURLWithRedirectURI(state, pkceCodes, RedirectURI)
}

func (o *ClaudeAuth) GenerateAuthURLWithRedirectURI(state string, pkceCodes *PKCECodes, redirectURI string) (string, string, error) {
	if pkceCodes == nil {
		return "", "", fmt.Errorf("PKCE codes are required")
	}
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		return "", "", fmt.Errorf("redirect URI is required")
	}

	params := [][2]string{
		{"code", "true"},
		{"client_id", ClientID},
		{"response_type", "code"},
		{"redirect_uri", redirectURI},
		{"scope", OAuthAuthorizeScope},
		{"code_challenge", pkceCodes.CodeChallenge},
		{"code_challenge_method", "S256"},
		{"state", state},
	}
	var query strings.Builder
	for index, param := range params {
		if index > 0 {
			query.WriteByte('&')
		}
		query.WriteString(url.QueryEscape(param[0]))
		query.WriteByte('=')
		query.WriteString(url.QueryEscape(param[1]))
	}
	authURL := AuthURL + "?" + query.String()
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
	splits := strings.SplitN(code, "#", 2)
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
	return o.ExchangeCodeForTokensWithRedirectURI(ctx, code, state, pkceCodes, RedirectURI)
}

func (o *ClaudeAuth) ExchangeCodeForTokensWithRedirectURI(ctx context.Context, code, state string, pkceCodes *PKCECodes, redirectURI string) (*ClaudeAuthBundle, error) {
	if pkceCodes == nil {
		return nil, fmt.Errorf("PKCE codes are required for token exchange")
	}
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		return nil, fmt.Errorf("redirect URI is required for token exchange")
	}
	newCode, _ := o.parseCodeAndState(code)
	reqBody := tokenExchangeRequest{
		GrantType:    "authorization_code",
		Code:         newCode,
		RedirectURI:  redirectURI,
		ClientID:     ClientID,
		CodeVerifier: pkceCodes.CodeVerifier,
		State:        state,
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
	req.Header.Set("Accept", claudeOAuthAccept)
	req.Header.Set("Accept-Encoding", claudeOAuthAcceptEncoding)
	req.Header.Set("User-Agent", claudeOAuthUserAgent)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("failed to close response body: %v", errClose)
		}
	}()

	body, err := readClaudeOAuthResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}
	// log.Debugf("Token response: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}
	// log.Debugf("Token response: %s", string(body))

	var tokenResp tokenResponse
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	o.backfillTokenIdentity(ctx, &tokenResp, true)

	// Create token data
	tokenData := ClaudeTokenData{
		AccessToken:           tokenResp.AccessToken,
		RefreshToken:          tokenResp.RefreshToken,
		Email:                 tokenResp.Account.EmailAddress,
		AccountUUID:           tokenResp.Account.UUID,
		OrganizationUUID:      tokenResp.Organization.UUID,
		Scope:                 tokenResp.Scope,
		RefreshTokenExpiresAt: claudeRefreshTokenExpiresAt(tokenResp.RefreshTokenExpiresIn, true),
		SubscriptionType:      claudeSubscriptionType(tokenResp.Organization.OrganizationType),
		RateLimitTier:         strings.TrimSpace(tokenResp.Organization.RateLimitTier),
		Expire:                time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
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
	return o.RefreshTokensWithScopes(ctx, refreshToken, nil, "", "")
}

// RefreshTokensWithScopes reproduces Claude Code's first-party scope migration
// and its one-time invalid_scope fallback to the stored scope list.
func (o *ClaudeAuth) RefreshTokensWithScopes(ctx context.Context, refreshToken string, storedScopes []string, subscriptionType, clientID string) (*ClaudeTokenData, error) {
	return o.refreshTokensWithProfileState(ctx, refreshToken, storedScopes, subscriptionType, "", clientID, false)
}

func (o *ClaudeAuth) refreshTokensWithProfileState(ctx context.Context, refreshToken string, storedScopes []string, subscriptionType, rateLimitTier, clientID string, enrichProfile bool) (*ClaudeTokenData, error) {
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

	storedScopes = append([]string(nil), storedScopes...)
	flightKey := refreshToken + "\x00" + clientID + "\x00" + subscriptionType + "\x00" + rateLimitTier + "\x00" + strconv.FormatBool(enrichProfile) + "\x00" + strings.Join(storedScopes, "\x00")
	result, err, _ := claudeRefreshGroup.Do(flightKey, func() (interface{}, error) {
		return o.refreshTokensSingleFlight(context.WithoutCancel(ctx), refreshToken, storedScopes, subscriptionType, rateLimitTier, clientID, enrichProfile)
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

func (o *ClaudeAuth) refreshTokensSingleFlight(ctx context.Context, refreshToken string, storedScopes []string, subscriptionType, rateLimitTier, clientID string, enrichProfile bool) (*ClaudeTokenData, error) {
	if blockedUntil := claudeRefreshBlockedUntil(refreshToken); blockedUntil.After(time.Now()) {
		return nil, &refreshHTTPError{
			status:    http.StatusTooManyRequests,
			message:   fmt.Sprintf("refresh temporarily blocked until %s", blockedUntil.Format(time.RFC3339)),
			retryable: false,
		}
	}

	storedClientID := strings.TrimSpace(clientID)
	firstParty := storedClientID == ""
	if firstParty {
		clientID = ClientID
	}
	storedHasInference := claudeScopeListContains(storedScopes, "user:inference")
	useMigratedScopes := firstParty && (storedHasInference || strings.TrimSpace(subscriptionType) != "")
	requestScopes := append([]string(nil), storedScopes...)
	if useMigratedScopes {
		requestScopes = strings.Fields(OAuthRefreshScope)
		for _, scope := range storedScopes {
			if scope == "user:projects:read" || scope == "user:projects:write" {
				requestScopes = appendUniqueClaudeScope(requestScopes, scope)
			}
		}
	}
	if len(requestScopes) == 0 {
		requestScopes = strings.Fields(OAuthRefreshScope)
	}

	tokenResp, err := o.refreshTokensRequest(ctx, refreshToken, clientID, requestScopes)
	if err != nil {
		var httpErr *refreshHTTPError
		if useMigratedScopes && storedHasInference && len(storedScopes) > 0 &&
			errors.As(err, &httpErr) && httpErr.status == http.StatusBadRequest && httpErr.oauthCode == "invalid_scope" {
			tokenResp, err = o.refreshTokensRequest(ctx, refreshToken, clientID, storedScopes)
		}
		if err != nil {
			return nil, err
		}
	}

	if strings.TrimSpace(tokenResp.RefreshToken) == "" {
		tokenResp.RefreshToken = refreshToken
	}
	if enrichProfile && firstParty && (strings.TrimSpace(subscriptionType) == "" || strings.TrimSpace(rateLimitTier) == "") {
		o.backfillTokenProfile(ctx, tokenResp, true, 1)
	} else {
		o.backfillTokenIdentity(ctx, tokenResp, false)
	}
	clearClaudeRefreshBlockedUntil(refreshToken)

	return &ClaudeTokenData{
		AccessToken:           tokenResp.AccessToken,
		RefreshToken:          tokenResp.RefreshToken,
		Email:                 tokenResp.Account.EmailAddress,
		AccountUUID:           tokenResp.Account.UUID,
		OrganizationUUID:      tokenResp.Organization.UUID,
		Scope:                 tokenResp.Scope,
		RefreshTokenExpiresAt: claudeRefreshTokenExpiresAt(tokenResp.RefreshTokenExpiresIn, false),
		SubscriptionType:      claudeSubscriptionType(tokenResp.Organization.OrganizationType),
		RateLimitTier:         strings.TrimSpace(tokenResp.Organization.RateLimitTier),
		ClientID:              storedClientID,
		Expire:                time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
	}, nil
}

func claudeScopeListContains(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

func appendUniqueClaudeScope(scopes []string, scope string) []string {
	if claudeScopeListContains(scopes, scope) {
		return scopes
	}
	return append(scopes, scope)
}

func parseClaudeOAuthErrorCode(body []byte) string {
	var envelope struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil || len(envelope.Error) == 0 {
		return ""
	}
	var stringCode string
	if json.Unmarshal(envelope.Error, &stringCode) == nil {
		return strings.TrimSpace(stringCode)
	}
	var objectCode struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(envelope.Error, &objectCode) == nil {
		return strings.TrimSpace(objectCode.Type)
	}
	return ""
}

func (o *ClaudeAuth) refreshTokensRequest(ctx context.Context, refreshToken, clientID string, scopes []string) (*tokenResponse, error) {
	reqBody := tokenRefreshRequest{
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
		ClientID:     clientID,
		Scope:        strings.Join(scopes, " "),
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
	req.Header.Set("Accept", claudeOAuthAccept)
	req.Header.Set("Accept-Encoding", claudeOAuthAcceptEncoding)
	req.Header.Set("User-Agent", claudeOAuthUserAgent)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token refresh request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := readClaudeOAuthResponse(resp)
	cancelRefresh()
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		message := http.StatusText(resp.StatusCode)
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := parseClaudeRetryAfter(resp)
			setClaudeRefreshBlockedUntil(refreshToken, time.Now().Add(retryAfter))
			return nil, &refreshHTTPError{status: resp.StatusCode, message: message, oauthCode: parseClaudeOAuthErrorCode(body), retryable: false}
		}
		return nil, &refreshHTTPError{
			status:    resp.StatusCode,
			message:   message,
			oauthCode: parseClaudeOAuthErrorCode(body),
			retryable: resp.StatusCode >= http.StatusInternalServerError,
		}
	}

	// log.Debugf("Token response: %s", string(body))

	var tokenResp tokenResponse
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	return &tokenResp, nil
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
		AccessToken:           bundle.TokenData.AccessToken,
		RefreshToken:          bundle.TokenData.RefreshToken,
		LastRefresh:           bundle.LastRefresh,
		Email:                 bundle.TokenData.Email,
		AccountUUID:           bundle.TokenData.AccountUUID,
		OrganizationUUID:      bundle.TokenData.OrganizationUUID,
		Scopes:                strings.Fields(bundle.TokenData.Scope),
		RefreshTokenExpiresAt: bundle.TokenData.RefreshTokenExpiresAt,
		SubscriptionType:      bundle.TokenData.SubscriptionType,
		RateLimitTier:         bundle.TokenData.RateLimitTier,
		ClientID:              bundle.TokenData.ClientID,
		Expire:                bundle.TokenData.Expire,
		Type:                  "claude",
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
	return o.refreshTokensWithProfileAndRetry(ctx, refreshToken, nil, "", "", "", maxRetries, false)
}

func (o *ClaudeAuth) RefreshTokensWithScopesAndRetry(ctx context.Context, refreshToken string, storedScopes []string, subscriptionType, rateLimitTier, clientID string, maxRetries int) (*ClaudeTokenData, error) {
	return o.refreshTokensWithProfileAndRetry(ctx, refreshToken, storedScopes, subscriptionType, rateLimitTier, clientID, maxRetries, true)
}

func (o *ClaudeAuth) refreshTokensWithProfileAndRetry(ctx context.Context, refreshToken string, storedScopes []string, subscriptionType, rateLimitTier, clientID string, maxRetries int, enrichProfile bool) (*ClaudeTokenData, error) {
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

		tokenData, err := o.refreshTokensWithProfileState(ctx, refreshToken, storedScopes, subscriptionType, rateLimitTier, clientID, enrichProfile)
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
	if scopes := strings.Fields(tokenData.Scope); len(scopes) > 0 {
		storage.Scopes = scopes
	}
	if tokenData.RefreshTokenExpiresAt > 0 {
		storage.RefreshTokenExpiresAt = tokenData.RefreshTokenExpiresAt
	}
	if tokenData.SubscriptionType != "" {
		storage.SubscriptionType = tokenData.SubscriptionType
	}
	if tokenData.RateLimitTier != "" {
		storage.RateLimitTier = tokenData.RateLimitTier
	}
	storage.ClientID = tokenData.ClientID
	storage.Expire = tokenData.Expire
}
