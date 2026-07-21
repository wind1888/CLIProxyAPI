package helps

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestOfficialClaudeCodeOAuthProfile(t *testing.T) {
	profile := OfficialClaudeCodeOAuthProfile()
	if ClaudeCodeDangerousDirectBrowserAccessHeader != "Anthropic-Dangerous-Direct-Browser-Access" {
		t.Fatalf("dangerous header name = %q", ClaudeCodeDangerousDirectBrowserAccessHeader)
	}
	if ClaudeCodeFirstPartyAPIHost != "api.anthropic.com" {
		t.Fatalf("first-party host = %q", ClaudeCodeFirstPartyAPIHost)
	}
	if profile.Version != "2.1.216" {
		t.Fatalf("Version = %q, want 2.1.216", profile.Version)
	}
	if profile.Entrypoint != "sdk-cli" {
		t.Fatalf("Entrypoint = %q, want sdk-cli", profile.Entrypoint)
	}
	if profile.UserAgent != "claude-cli/2.1.216 (external, sdk-cli)" {
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

func TestClaudeCodeStaticSystemPromptToolSetGoldens(t *testing.T) {
	tests := []struct {
		name                      string
		hasBash, hasTask, hasTodo bool
		wantBytes, wantRunes      int
		wantSHA256                string
	}{
		{name: "no bash no task", wantBytes: 10604, wantRunes: 10598, wantSHA256: "6ed0608ab0f8a2e5966a72e22ffe1fc04a1ff6d5e220393c1ef30b7c9e336b30"},
		{name: "bash no task", hasBash: true, wantBytes: 10580, wantRunes: 10574, wantSHA256: "e75c68291d755989d302e3beaf20a71b48ab252dc1e3bde5f795f33ea6d647f2"},
		{name: "no bash TaskCreate", hasTask: true, wantBytes: 10706, wantRunes: 10700, wantSHA256: "f54f80eb51daf39452d2b6702ed6b97db00dd76a64358425eda56a8ad38bbac8"},
		{name: "bash TaskCreate", hasBash: true, hasTask: true, wantBytes: 10682, wantRunes: 10676, wantSHA256: "5930501c4490d97d31d93534da66b5d54a1d71fb1e043a1dc4939bf142c22b1b"},
		{name: "no bash TodoWrite", hasTodo: true, wantBytes: 10705, wantRunes: 10699, wantSHA256: "ef843434cb7fbc2b5b56f28527214ba85da7c50d80902e35140358406625c93f"},
		{name: "bash TodoWrite", hasBash: true, hasTodo: true, wantBytes: 10681, wantRunes: 10675, wantSHA256: "827a2168988cb4e2034e459511e9ff1023ff67d7f11dfe680d1eaa1116a4bbd2"},
		{name: "TaskCreate wins", hasBash: true, hasTask: true, hasTodo: true, wantBytes: 10682, wantRunes: 10676, wantSHA256: "5930501c4490d97d31d93534da66b5d54a1d71fb1e043a1dc4939bf142c22b1b"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prompt := ClaudeCodeStaticSystemPromptForTools(test.hasBash, test.hasTask, test.hasTodo)
			if len(prompt) != test.wantBytes || utf8.RuneCountInString(prompt) != test.wantRunes {
				t.Fatalf("prompt size = %d bytes/%d runes, want %d/%d", len(prompt), utf8.RuneCountInString(prompt), test.wantBytes, test.wantRunes)
			}
			sum := sha256.Sum256([]byte(prompt))
			if got := hex.EncodeToString(sum[:]); got != test.wantSHA256 {
				t.Fatalf("prompt sha256 = %s, want %s", got, test.wantSHA256)
			}
		})
	}
	if ClaudeCodeStaticSystemPrompt != ClaudeCodeStaticSystemPromptForTools(true, true, false) {
		t.Fatal("default static constant diverged from Bash+TaskCreate official variant")
	}
}

func TestClaudeCodeLeanStaticSystemPromptGoldens(t *testing.T) {
	tests := []struct {
		name       string
		model      string
		wantBytes  int
		wantRunes  int
		wantSHA256 string
	}{
		{name: "Opus 4.8", model: "claude-opus-4-8", wantBytes: 1156, wantRunes: 1152, wantSHA256: "a90654a30cb6d5f8cd1d7218e90404a10f91055bcc3c0b97a93eb988382d794a"},
		{name: "Fable 5", model: "claude-fable-5", wantBytes: 1214, wantRunes: 1210, wantSHA256: "3b27271fa44cde325c8c45022d975b4239be67b3a39e31494e6ed1ff4654015d"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prompt := ClaudeCodeStaticSystemPromptForModel(test.model, true, true, false)
			if len(prompt) != test.wantBytes || utf8.RuneCountInString(prompt) != test.wantRunes {
				t.Fatalf("prompt size = %d bytes/%d runes, want %d/%d", len(prompt), utf8.RuneCountInString(prompt), test.wantBytes, test.wantRunes)
			}
			sum := sha256.Sum256([]byte(prompt))
			if got := hex.EncodeToString(sum[:]); got != test.wantSHA256 {
				t.Fatalf("prompt sha256 = %s, want %s", got, test.wantSHA256)
			}
		})
	}
}

func TestClaudeCodeDynamicPromptPrefixGoldens(t *testing.T) {
	tests := []struct {
		name       string
		model      string
		wantBytes  int
		wantRunes  int
		wantSHA256 string
	}{
		{name: "normal", model: "claude-sonnet-4-6", wantBytes: 1713, wantRunes: 1699, wantSHA256: "d741f97cb47aee81682c9ae1637afbd6956f217ea28149cf250c5c71bc6726d8"},
		{name: "Opus 4.8", model: "claude-opus-4-8", wantBytes: 1094, wantRunes: 1088, wantSHA256: "a45a0afd3d67a9c05c23a0abb12515d877e88a8e135ff1ce9fda4e1bd1710c6c"},
		{name: "Fable 5", model: "claude-fable-5", wantBytes: 4140, wantRunes: 4120, wantSHA256: "9005a1341feef170180de927086df3c291914815ba29ec2ce73d61cfe76fd2f2"},
		{name: "Mythos 5", model: "claude-mythos-5", wantBytes: 3444, wantRunes: 3424, wantSHA256: "a7b81d468468ccba4d4625be4b550c7c553d1dc5c5936d9a488ff11ba911c67d"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prompt := ClaudeCodeDynamicPromptPrefixForModel(test.model)
			if len(prompt) != test.wantBytes || utf8.RuneCountInString(prompt) != test.wantRunes {
				t.Fatalf("prompt size = %d bytes/%d runes, want %d/%d", len(prompt), utf8.RuneCountInString(prompt), test.wantBytes, test.wantRunes)
			}
			sum := sha256.Sum256([]byte(prompt))
			if got := hex.EncodeToString(sum[:]); got != test.wantSHA256 {
				t.Fatalf("prompt sha256 = %s, want %s", got, test.wantSHA256)
			}
		})
	}
}

func TestClaudeCodePromptOverrideGoldens(t *testing.T) {
	forceLean := true
	forceNormal := false
	staticTests := []struct {
		name        string
		model       string
		simple      *bool
		investigate string
		wantBytes   int
		wantRunes   int
		wantSHA256  string
	}{
		{name: "Sonnet forced lean", model: "claude-sonnet-4-6", simple: &forceLean, wantBytes: 1156, wantRunes: 1152, wantSHA256: "a90654a30cb6d5f8cd1d7218e90404a10f91055bcc3c0b97a93eb988382d794a"},
		{name: "Opus 4.8 forced normal", model: "claude-opus-4-8", simple: &forceNormal, wantBytes: 10682, wantRunes: 10676, wantSHA256: "5930501c4490d97d31d93534da66b5d54a1d71fb1e043a1dc4939bf142c22b1b"},
		{name: "Fable forced normal mid-conv", model: "claude-fable-5", simple: &forceNormal, wantBytes: 10622, wantRunes: 10616, wantSHA256: "bb34b77ce7a0fdd71d1b1e4824392add6cdb967ad6106ed4521f01030d2269d3"},
		{name: "Opus 4.7 additive static", model: "claude-opus-4-7", investigate: ClaudeCodeInvestigateFirstAdditive, wantBytes: 10682, wantRunes: 10676, wantSHA256: "5930501c4490d97d31d93534da66b5d54a1d71fb1e043a1dc4939bf142c22b1b"},
		{name: "Opus 4.7 compact static", model: "claude-opus-4-7", investigate: ClaudeCodeInvestigateFirstCompact, wantBytes: 7475, wantRunes: 7471, wantSHA256: "103e442be5dbafec4d2ae259c552019ac39563c17471ef539ffe27b4fabfd7ad"},
	}
	for _, test := range staticTests {
		t.Run(test.name, func(t *testing.T) {
			prompt := ClaudeCodeStaticSystemPromptForOptions(test.model, true, true, false, test.simple, test.investigate)
			if len(prompt) != test.wantBytes || utf8.RuneCountInString(prompt) != test.wantRunes {
				t.Fatalf("static prompt size = %d bytes/%d runes, want %d/%d", len(prompt), utf8.RuneCountInString(prompt), test.wantBytes, test.wantRunes)
			}
			sum := sha256.Sum256([]byte(prompt))
			if got := hex.EncodeToString(sum[:]); got != test.wantSHA256 {
				t.Fatalf("static prompt sha256 = %s, want %s", got, test.wantSHA256)
			}
		})
	}

	dynamicTests := []struct {
		name        string
		model       string
		simple      *bool
		investigate string
		wantBytes   int
		wantRunes   int
		wantSHA256  string
	}{
		{name: "Sonnet forced lean", model: "claude-sonnet-4-6", simple: &forceLean, wantBytes: 1094, wantRunes: 1088, wantSHA256: "a45a0afd3d67a9c05c23a0abb12515d877e88a8e135ff1ce9fda4e1bd1710c6c"},
		{name: "Opus 4.8 forced normal", model: "claude-opus-4-8", simple: &forceNormal, wantBytes: 1713, wantRunes: 1699, wantSHA256: "d741f97cb47aee81682c9ae1637afbd6956f217ea28149cf250c5c71bc6726d8"},
		{name: "Fable forced normal", model: "claude-fable-5", simple: &forceNormal, wantBytes: 3503, wantRunes: 3485, wantSHA256: "55c9fc052e201decce0708d1737b5b611d568debb7c6634226599e73fbd5336f"},
		{name: "Mythos forced normal", model: "claude-mythos-5", simple: &forceNormal, wantBytes: 2807, wantRunes: 2789, wantSHA256: "89ad95b702797ff89b5579dace2167d34b004ef1fefcf41727aa5d9bc94a75a4"},
		{name: "Opus 4.7 additive", model: "claude-opus-4-7", investigate: ClaudeCodeInvestigateFirstAdditive, wantBytes: 2062, wantRunes: 2046, wantSHA256: "f167674d375a45f7aede7842a467355bcbbd4fed9662262afbdd970948aa9f9e"},
		{name: "Opus 4.7 compact", model: "claude-opus-4-7", investigate: ClaudeCodeInvestigateFirstCompact, wantBytes: 2062, wantRunes: 2046, wantSHA256: "f167674d375a45f7aede7842a467355bcbbd4fed9662262afbdd970948aa9f9e"},
	}
	for _, test := range dynamicTests {
		t.Run(test.name, func(t *testing.T) {
			prompt := ClaudeCodeDynamicPromptPrefixForOptions(test.model, test.simple, test.investigate)
			if len(prompt) != test.wantBytes || utf8.RuneCountInString(prompt) != test.wantRunes {
				t.Fatalf("dynamic prompt size = %d bytes/%d runes, want %d/%d", len(prompt), utf8.RuneCountInString(prompt), test.wantBytes, test.wantRunes)
			}
			sum := sha256.Sum256([]byte(prompt))
			if got := hex.EncodeToString(sum[:]); got != test.wantSHA256 {
				t.Fatalf("dynamic prompt sha256 = %s, want %s", got, test.wantSHA256)
			}
		})
	}
}

func TestClaudeCodePromptEnvironmentValueParsing(t *testing.T) {
	for value, want := range map[string]bool{"1": true, "true": true, "yes": true, "on": true, "0": false, "false": false, "no": false, "off": false} {
		got := ClaudeCodeSimpleSystemPromptOverride(value)
		if got == nil || *got != want {
			t.Fatalf("simple override %q = %v, want %t", value, got, want)
		}
	}
	if got := ClaudeCodeSimpleSystemPromptOverride("unknown"); got != nil {
		t.Fatalf("unknown simple override = %v, want nil", *got)
	}
	for value, want := range map[string]string{
		"compact":  ClaudeCodeInvestigateFirstCompact,
		"additive": ClaudeCodeInvestigateFirstAdditive,
		"true":     ClaudeCodeInvestigateFirstAdditive,
		"off":      ClaudeCodeInvestigateFirstOff,
		"unknown":  ClaudeCodeInvestigateFirstOff,
	} {
		if got := ClaudeCodeInvestigateFirstMode(value); got != want {
			t.Fatalf("investigate mode %q = %q, want %q", value, got, want)
		}
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
	haikuWant := []string{
		"oauth-2025-04-20",
		"interleaved-thinking-2025-05-14",
		"thinking-token-count-2026-05-13",
		"context-management-2025-06-27",
		"prompt-caching-scope-2026-01-05",
		"claude-code-20250219",
	}
	if haikuGot := strings.Split(ClaudeCodeHaiku45OAuthBetaHeader, ","); !reflect.DeepEqual(haikuGot, haikuWant) {
		t.Fatalf("Haiku 4.5 OAuth base betas = %#v, want captured order %#v", haikuGot, haikuWant)
	}
	if ClaudeCodeAdvancedToolUseBeta != "advanced-tool-use-2025-11-20" {
		t.Fatalf("advanced tool beta = %q", ClaudeCodeAdvancedToolUseBeta)
	}
	if ClaudeCodeMidConversationSystemBeta != "mid-conversation-system-2026-04-07" {
		t.Fatalf("mid-conversation system beta = %q", ClaudeCodeMidConversationSystemBeta)
	}
	if ClaudeCodeContext1MBeta != "context-1m-2025-08-07" {
		t.Fatalf("context 1M beta = %q", ClaudeCodeContext1MBeta)
	}
	if ClaudeCodeEffortBeta != "effort-2025-11-24" {
		t.Fatalf("effort beta = %q", ClaudeCodeEffortBeta)
	}
	if ClaudeCodeServerSideFallbackBeta != "server-side-fallback-2026-06-01" {
		t.Fatalf("server-side fallback beta = %q", ClaudeCodeServerSideFallbackBeta)
	}
	if ClaudeCodeFallbackCreditBeta != "fallback-credit-2026-06-01" {
		t.Fatalf("fallback credit beta = %q", ClaudeCodeFallbackCreditBeta)
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
