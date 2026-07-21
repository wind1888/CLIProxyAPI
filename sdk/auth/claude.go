package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	// legacy client removed
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// ClaudeAuthenticator implements the OAuth login flow for Anthropic Claude accounts.
type ClaudeAuthenticator struct {
	CallbackPort int
}

// NewClaudeAuthenticator constructs a Claude authenticator with default settings.
func NewClaudeAuthenticator() *ClaudeAuthenticator {
	return &ClaudeAuthenticator{}
}

func (a *ClaudeAuthenticator) Provider() string {
	return "claude"
}

func (a *ClaudeAuthenticator) RefreshLead() *time.Duration {
	return new(5 * time.Minute)
}

func claudeOAuthScopeContains(rawScope, target string) bool {
	for _, scope := range strings.Fields(rawScope) {
		if scope == target {
			return true
		}
	}
	return false
}

func useClaudeManualOAuth(noBrowser, browserAvailable bool) bool {
	return noBrowser || !browserAvailable
}

func parseClaudeManualOAuthInput(input, generatedState string) (*claude.OAuthResult, string, error) {
	parsed, err := misc.ParseOAuthCallback(input)
	if err != nil {
		parts := strings.SplitN(strings.TrimSpace(input), "#", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			parsed = &misc.OAuthCallback{Code: parts[0], State: parts[1]}
			err = nil
		}
	}
	if err != nil || parsed == nil {
		return nil, "", err
	}
	return &claude.OAuthResult{
		Code: parsed.Code,
		// Claude's hosted copy/paste response contains code#state. The state
		// generated for this PKCE attempt remains authoritative for exchange.
		State: generatedState,
		Error: parsed.Error,
	}, parsed.ErrorDescription, nil
}

func promptClaudeManualOAuth(prompt func(string) (string, error), generatedState string) (*claude.OAuthResult, string, error) {
	if prompt == nil {
		return nil, "", fmt.Errorf("claude manual authentication requires an interactive prompt")
	}
	for {
		input, err := prompt("Paste the Claude callback URL or authorization code: ")
		if err != nil {
			return nil, "", err
		}
		result, description, errParse := parseClaudeManualOAuthInput(input, generatedState)
		if errParse != nil {
			return nil, "", errParse
		}
		if result != nil {
			return result, description, nil
		}
	}
}

func (a *ClaudeAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	callbackPort := a.CallbackPort
	if opts.CallbackPort > 0 {
		callbackPort = opts.CallbackPort
	}

	pkceCodes, err := claude.GeneratePKCECodes()
	if err != nil {
		return nil, fmt.Errorf("claude pkce generation failed: %w", err)
	}

	state, err := claude.GenerateOAuthState()
	if err != nil {
		return nil, fmt.Errorf("claude state generation failed: %w", err)
	}

	authSvc := claude.NewClaudeAuth(cfg)
	manualRedirectURI := claude.RedirectURI
	manualAuthURL, returnedState, err := authSvc.GenerateAuthURLWithRedirectURI(state, pkceCodes, manualRedirectURI)
	if err != nil {
		return nil, fmt.Errorf("claude manual authorization url generation failed: %w", err)
	}
	state = returnedState

	browserAvailable := false
	if !opts.NoBrowser {
		browserAvailable = browser.IsAvailable()
	}
	var (
		result            *claude.OAuthResult
		manualDescription string
		oauthServer       *claude.OAuthServer
		localRedirectURI  string
		usedLocalCallback bool
		useManualCallback = useClaudeManualOAuth(opts.NoBrowser, browserAvailable)
	)

	if useManualCallback {
		fmt.Printf("Open this URL to sign in: %s\n", manualAuthURL)
		result, manualDescription, err = promptClaudeManualOAuth(opts.Prompt, state)
		if err != nil {
			return nil, err
		}
	} else {
		oauthServer = claude.NewOAuthServer(callbackPort)
		oauthServer.SetExpectedState(state)
		if err = oauthServer.Start(); err != nil {
			if strings.Contains(err.Error(), "already in use") {
				return nil, claude.NewAuthenticationError(claude.ErrPortInUse, err)
			}
			return nil, claude.NewAuthenticationError(claude.ErrServerStartFailed, err)
		}
		defer func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if stopErr := oauthServer.Stop(stopCtx); stopErr != nil {
				log.Warnf("claude oauth server stop error: %v", stopErr)
			}
		}()

		localRedirectURI = oauthServer.RedirectURI()
		automaticAuthURL, automaticState, errURL := authSvc.GenerateAuthURLWithRedirectURI(state, pkceCodes, localRedirectURI)
		if errURL != nil {
			return nil, fmt.Errorf("claude automatic authorization url generation failed: %w", errURL)
		}
		state = automaticState
		fmt.Println("Opening browser to sign in…")
		fmt.Printf("If the browser didn't open, visit: %s\n", automaticAuthURL)

		if errOpen := browser.OpenURL(automaticAuthURL); errOpen != nil {
			log.Warnf("Failed to open browser automatically: %v", errOpen)
			if opts.Prompt != nil {
				stopCtx, cancelStop := context.WithTimeout(context.Background(), 2*time.Second)
				_ = oauthServer.Stop(stopCtx)
				cancelStop()
				fmt.Printf("Open this URL to sign in: %s\n", manualAuthURL)
				result, manualDescription, err = promptClaudeManualOAuth(opts.Prompt, state)
				if err != nil {
					return nil, err
				}
			}
		}
		if result == nil {
			result, err = oauthServer.WaitForCallbackContext(ctx, 5*time.Minute)
			if err != nil {
				if oauthServer.HasPendingResponse() {
					oauthServer.FailCallback(err)
				}
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return nil, err
				}
				if strings.Contains(strings.ToLower(err.Error()), "timeout") {
					return nil, claude.NewAuthenticationError(claude.ErrCallbackTimeout, err)
				}
				return nil, err
			}
			usedLocalCallback = true
		}
	}

	if result.Code == "" && result.Error != "" {
		oauthErr := claude.NewOAuthError(result.Error, manualDescription, http.StatusBadRequest)
		if usedLocalCallback {
			oauthServer.FailCallback(oauthErr)
		}
		return nil, oauthErr
	}

	if result.State != state {
		log.Error("Claude OAuth state mismatch")
		stateErr := claude.NewAuthenticationError(claude.ErrInvalidState, fmt.Errorf("state mismatch"))
		if usedLocalCallback {
			oauthServer.FailCallback(stateErr)
		}
		return nil, stateErr
	}

	log.Debug("Claude authorization code received; exchanging for tokens")

	exchangeRedirectURI := manualRedirectURI
	if usedLocalCallback {
		exchangeRedirectURI = localRedirectURI
	}
	authBundle, err := authSvc.ExchangeCodeForTokensWithRedirectURI(ctx, result.Code, state, pkceCodes, exchangeRedirectURI)
	if err != nil {
		if usedLocalCallback {
			oauthServer.FailCallback(err)
		}
		log.Errorf("Token exchange failed: %v", err)
		return nil, claude.NewAuthenticationError(claude.ErrCodeExchangeFailed, err)
	}
	if usedLocalCallback {
		if claudeOAuthScopeContains(authBundle.TokenData.Scope, "user:inference") {
			oauthServer.SetSuccessURL(claude.OAuthSuccessURL)
		} else {
			oauthServer.SetSuccessURL(claude.OAuthBuyCreditsURL)
		}
		oauthServer.CompleteCallback()
	}

	tokenStorage := authSvc.CreateTokenStorage(authBundle)

	if tokenStorage == nil || tokenStorage.AccessToken == "" {
		return nil, fmt.Errorf("claude token storage missing account information")
	}

	fileName, errFileName := tokenStorage.TokenFileName()
	if errFileName != nil {
		return nil, errFileName
	}
	metadata := map[string]any{
		"access_token":             tokenStorage.AccessToken,
		"refresh_token":            tokenStorage.RefreshToken,
		"last_refresh":             tokenStorage.LastRefresh,
		"expired":                  tokenStorage.Expire,
		"email":                    tokenStorage.Email,
		"account_uuid":             tokenStorage.AccountUUID,
		"organization_uuid":        tokenStorage.OrganizationUUID,
		"scopes":                   append([]string(nil), tokenStorage.Scopes...),
		"refresh_token_expires_at": tokenStorage.RefreshTokenExpiresAt,
		"subscription_type":        tokenStorage.SubscriptionType,
		"rate_limit_tier":          tokenStorage.RateLimitTier,
		"client_id":                tokenStorage.ClientID,
		"type":                     "claude",
		"auth_kind":                "oauth",
	}

	fmt.Println("Claude authentication successful")
	if authBundle.APIKey != "" {
		fmt.Println("Claude API key obtained and stored")
	}

	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Storage:  tokenStorage,
		Metadata: metadata,
		Attributes: map[string]string{
			"auth_kind": "oauth",
		},
	}, nil
}
