package helps

import (
	"net/url"
	"strings"
)

const (
	ClaudeCodeOAuthVersion    = "2.1.216"
	ClaudeCodeOAuthEntrypoint = "sdk-cli"
	ClaudeCodeOAuthUserAgent  = "claude-cli/2.1.216 (external, sdk-cli)"
	ClaudeCodeSDKVersion      = "0.94.0"
	ClaudeCodeRuntimeVersion  = "v26.3.0"
	ClaudeCodeStainlessOS     = "MacOS"
	ClaudeCodeStainlessArch   = "arm64"
	ClaudeCodeRequestTimeout  = "600"

	ClaudeCodeOAuthBetaHeader           = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05"
	ClaudeCodeHaiku45OAuthBetaHeader    = "oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,claude-code-20250219"
	ClaudeCodeMidConversationSystemBeta = "mid-conversation-system-2026-04-07"
	ClaudeCodeContext1MBeta             = "context-1m-2025-08-07"
	ClaudeCodeAdvancedToolUseBeta       = "advanced-tool-use-2025-11-20"
	ClaudeCodeEffortBeta                = "effort-2025-11-24"
	ClaudeCodeServerSideFallbackBeta    = "server-side-fallback-2026-06-01"
	ClaudeCodeFallbackCreditBeta        = "fallback-credit-2026-06-01"
	ClaudeCodeExtendedCacheTTLBeta      = "extended-cache-ttl-2025-04-11"

	ClaudeCodeDangerousDirectBrowserAccessHeader = "Anthropic-Dangerous-Direct-Browser-Access"
	ClaudeCodeDangerousDirectBrowserAccessValue  = "true"

	ClaudeCodeOAuthCacheControlType = "ephemeral"
	ClaudeCodeOAuthCacheTTL         = "1h"
	ClaudeCodeOAuthGlobalCacheScope = "global"
	ClaudeCodeContextManagementJSON = `{"edits":[{"type":"clear_thinking_20251015","keep":"all"}]}`

	ClaudeCodeFirstPartyAPIHost = "api.anthropic.com"
)

// ClaudeCodeOAuthRequestProfile is the captured Claude Code request profile
// for a subscription OAuth request sent directly to Anthropic's first-party API.
type ClaudeCodeOAuthRequestProfile struct {
	Version                      string
	Entrypoint                   string
	UserAgent                    string
	SDKVersion                   string
	RuntimeVersion               string
	OS                           string
	Arch                         string
	Timeout                      string
	BetaHeader                   string
	DangerousDirectBrowserAccess string
	CacheControlType             string
	CacheTTL                     string
	GlobalCacheScope             string
}

// OfficialClaudeCodeOAuthProfile returns the immutable request values captured
// from Claude Code 2.1.216 running through the sdk-cli entrypoint.
func OfficialClaudeCodeOAuthProfile() ClaudeCodeOAuthRequestProfile {
	return ClaudeCodeOAuthRequestProfile{
		Version:                      ClaudeCodeOAuthVersion,
		Entrypoint:                   ClaudeCodeOAuthEntrypoint,
		UserAgent:                    ClaudeCodeOAuthUserAgent,
		SDKVersion:                   ClaudeCodeSDKVersion,
		RuntimeVersion:               ClaudeCodeRuntimeVersion,
		OS:                           ClaudeCodeStainlessOS,
		Arch:                         ClaudeCodeStainlessArch,
		Timeout:                      ClaudeCodeRequestTimeout,
		BetaHeader:                   ClaudeCodeOAuthBetaHeader,
		DangerousDirectBrowserAccess: ClaudeCodeDangerousDirectBrowserAccessValue,
		CacheControlType:             ClaudeCodeOAuthCacheControlType,
		CacheTTL:                     ClaudeCodeOAuthCacheTTL,
		GlobalCacheScope:             ClaudeCodeOAuthGlobalCacheScope,
	}
}

// IsClaudeFirstPartyAPIURL reports whether target is the direct Anthropic API.
// An explicit default TLS port is equivalent to an omitted port.
func IsClaudeFirstPartyAPIURL(target *url.URL) bool {
	if target == nil || target.User != nil || !strings.EqualFold(target.Scheme, "https") {
		return false
	}
	return strings.EqualFold(target.Host, ClaudeCodeFirstPartyAPIHost) ||
		strings.EqualFold(target.Host, ClaudeCodeFirstPartyAPIHost+":443")
}
