package helps

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestOfficialClaudeCodeOAuthProfile(t *testing.T) {
	profile := OfficialClaudeCodeOAuthProfile()
	if ClaudeCodeDangerousDirectBrowserAccessHeader != "Anthropic-Dangerous-Direct-Browser-Access" {
		t.Fatalf("dangerous header name = %q", ClaudeCodeDangerousDirectBrowserAccessHeader)
	}
	if ClaudeCodeFirstPartyAPIHost != "api.anthropic.com" {
		t.Fatalf("first-party host = %q", ClaudeCodeFirstPartyAPIHost)
	}
	if profile.Version != "2.1.215" {
		t.Fatalf("Version = %q, want 2.1.215", profile.Version)
	}
	if profile.Entrypoint != "sdk-cli" {
		t.Fatalf("Entrypoint = %q, want sdk-cli", profile.Entrypoint)
	}
	if profile.UserAgent != "claude-cli/2.1.215 (external, sdk-cli)" {
		t.Fatalf("UserAgent = %q", profile.UserAgent)
	}
	if profile.SDKVersion != "0.94.0" || profile.RuntimeVersion != "v26.3.0" || profile.OS != "MacOS" || profile.Arch != "arm64" || profile.Timeout != "600" {
		t.Fatalf("runtime profile = sdk %q runtime %q os %q arch %q timeout %q", profile.SDKVersion, profile.RuntimeVersion, profile.OS, profile.Arch, profile.Timeout)
	}
	if profile.DangerousDirectBrowserAccess != "true" {
		t.Fatalf("DangerousDirectBrowserAccess = %q, want true", profile.DangerousDirectBrowserAccess)
	}
	if profile.CacheControlType != "ephemeral" || profile.CacheTTL != "1h" || profile.GlobalCacheScope != "global" {
		t.Fatalf("cache profile = type %q, ttl %q, scope %q", profile.CacheControlType, profile.CacheTTL, profile.GlobalCacheScope)
	}
}

func TestClaudeCodeOAuthBetaHeaderCapturedOrder(t *testing.T) {
	want := []string{
		"claude-code-20250219",
		"oauth-2025-04-20",
		"interleaved-thinking-2025-05-14",
		"thinking-token-count-2026-05-13",
		"context-management-2025-06-27",
		"prompt-caching-scope-2026-01-05",
	}
	got := strings.Split(OfficialClaudeCodeOAuthProfile().BetaHeader, ",")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OAuth base betas = %#v, want captured order %#v", got, want)
	}
	if ClaudeCodeAdvancedToolUseBeta != "advanced-tool-use-2025-11-20" {
		t.Fatalf("advanced tool beta = %q", ClaudeCodeAdvancedToolUseBeta)
	}
	if ClaudeCodeEffortBeta != "effort-2025-11-24" {
		t.Fatalf("effort beta = %q", ClaudeCodeEffortBeta)
	}
	if ClaudeCodeExtendedCacheTTLBeta != "extended-cache-ttl-2025-04-11" {
		t.Fatalf("extended cache TTL beta = %q", ClaudeCodeExtendedCacheTTLBeta)
	}
}

func TestIsClaudeFirstPartyAPIURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "messages", raw: "https://api.anthropic.com/v1/messages?beta=true", want: true},
		{name: "explicit default port", raw: "https://api.anthropic.com:443/v1/messages", want: true},
		{name: "case insensitive authority", raw: "HTTPS://API.ANTHROPIC.COM/v1/messages", want: true},
		{name: "plain http", raw: "http://api.anthropic.com/v1/messages", want: false},
		{name: "non-default port", raw: "https://api.anthropic.com:8443/v1/messages", want: false},
		{name: "subdomain", raw: "https://proxy.api.anthropic.com/v1/messages", want: false},
		{name: "suffix attack", raw: "https://api.anthropic.com.example/v1/messages", want: false},
		{name: "userinfo", raw: "https://user@api.anthropic.com/v1/messages", want: false},
		{name: "trailing dot", raw: "https://api.anthropic.com./v1/messages", want: false},
		{name: "custom base", raw: "https://claude.example/v1/messages", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, errParse := url.Parse(test.raw)
			if errParse != nil {
				t.Fatalf("parse URL: %v", errParse)
			}
			if got := IsClaudeFirstPartyAPIURL(target); got != test.want {
				t.Fatalf("IsClaudeFirstPartyAPIURL(%q) = %v, want %v", test.raw, got, test.want)
			}
		})
	}

	if IsClaudeFirstPartyAPIURL(nil) {
		t.Fatal("IsClaudeFirstPartyAPIURL(nil) = true, want false")
	}
}
