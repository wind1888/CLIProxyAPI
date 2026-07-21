package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func resetClaudeDeviceProfileCache() {
	helps.ResetClaudeDeviceProfileCache()
}

func malformedClaudeTreeSignatureForClaudeExecutorTest() string {
	return base64.StdEncoding.EncodeToString([]byte{0x12, 0xFF, 0xFE, 0xFD})
}

func newClaudeHeaderTestRequest(t *testing.T, incoming http.Header) *http.Request {
	t.Helper()

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginReq := httptest.NewRequest(http.MethodPost, "http://localhost/v1/messages", nil)
	ginReq.Header = incoming.Clone()
	ginCtx.Request = ginReq

	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	return req.WithContext(context.WithValue(req.Context(), "gin", ginCtx))
}

func assertClaudeFingerprint(t *testing.T, headers http.Header, userAgent, pkgVersion, runtimeVersion, osName, arch string) {
	t.Helper()

	if got := headers.Get("User-Agent"); got != userAgent {
		t.Fatalf("User-Agent = %q, want %q", got, userAgent)
	}
	if got := headers.Get("X-Stainless-Package-Version"); got != pkgVersion {
		t.Fatalf("X-Stainless-Package-Version = %q, want %q", got, pkgVersion)
	}
	if got := headers.Get("X-Stainless-Runtime-Version"); got != runtimeVersion {
		t.Fatalf("X-Stainless-Runtime-Version = %q, want %q", got, runtimeVersion)
	}
	if got := headers.Get("X-Stainless-Os"); got != osName {
		t.Fatalf("X-Stainless-Os = %q, want %q", got, osName)
	}
	if got := headers.Get("X-Stainless-Arch"); got != arch {
		t.Fatalf("X-Stainless-Arch = %q, want %q", got, arch)
	}
}

func assertClaudeCodeMetadataUserID(t *testing.T, userID string) {
	t.Helper()

	if !helps.IsValidUserID(userID) {
		t.Fatalf("metadata.user_id %q is not valid Claude Code JSON", userID)
	}
	if got := gjson.Get(userID, "device_id").String(); !helps.IsValidClaudeCodeDeviceID(got) {
		t.Fatalf("metadata.user_id.device_id = %q, want 64-char hex", got)
	}
	if got := gjson.Get(userID, "account_uuid").String(); got != "" {
		t.Fatalf("metadata.user_id.account_uuid = %q, want empty", got)
	}
	if got := gjson.Get(userID, "session_id").String(); got == "" {
		t.Fatalf("metadata.user_id.session_id is empty in %q", userID)
	}
}

func TestApplyClaudeHeaders_UsesConfiguredBaselineFingerprint(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			Timeout:                "900",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-baseline",
		Attributes: map[string]string{
			"api_key":                            "key-baseline",
			"header:User-Agent":                  "evil-client/9.9",
			"header:X-Stainless-Os":              "Linux",
			"header:X-Stainless-Arch":            "x64",
			"header:X-Stainless-Package-Version": "9.9.9",
		},
	}
	incoming := http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	}

	req := newClaudeHeaderTestRequest(t, incoming)
	applyClaudeHeaders(req, auth, "key-baseline", false, nil, cfg, nil)

	assertClaudeFingerprint(t, req.Header, "evil-client/9.9", "9.9.9", "v24.5.0", "Linux", "x64")
	if got := req.Header.Get("X-Stainless-Timeout"); got != "900" {
		t.Fatalf("X-Stainless-Timeout = %q, want %q", got, "900")
	}
}

func TestApplyClaudeHeaders_DefaultsDangerousDirectBrowserAccessForAPIKey(t *testing.T) {
	resetClaudeDeviceProfileCache()

	req := newClaudeHeaderTestRequest(t, nil)
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{
			"api_key": "key-danger-default",
		},
	}

	if err := applyClaudeHeaders(req, auth, "key-danger-default", false, nil, &config.Config{}, nil); err != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", err)
	}

	if got := req.Header.Get("Anthropic-Dangerous-Direct-Browser-Access"); got != "true" {
		t.Fatalf("Anthropic-Dangerous-Direct-Browser-Access = %q, want true", got)
	}
}

func TestApplyClaudeHeaders_SendsDangerousDirectBrowserAccessForOAuth(t *testing.T) {
	resetClaudeDeviceProfileCache()

	req := newClaudeHeaderTestRequest(t, nil)
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{
			"access_token": "oauth-token-danger",
		},
	}

	if err := applyClaudeHeaders(req, auth, "oauth-token-danger", false, nil, &config.Config{}, nil); err != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", err)
	}

	if got := req.Header.Get("Anthropic-Dangerous-Direct-Browser-Access"); got != "true" {
		t.Fatalf("Anthropic-Dangerous-Direct-Browser-Access = %q, want true", got)
	}
}

func TestApplyClaudeHeaders_MergesIncomingBetaWithOfficialDefaults(t *testing.T) {
	resetClaudeDeviceProfileCache()

	incoming := http.Header{
		"Anthropic-Beta": []string{"custom-beta-2026-07-20,context-management-2025-06-27"},
	}
	req := newClaudeHeaderTestRequest(t, incoming)
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{
			"api_key": "key-beta",
		},
	}

	if err := applyClaudeHeaders(req, auth, "key-beta", false, []string{"extra-beta-2026-07-20"}, &config.Config{}, incoming); err != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", err)
	}

	got := req.Header.Get("Anthropic-Beta")
	want := defaultClaudeCodeBetas + ",custom-beta-2026-07-20,extra-beta-2026-07-20"
	if got != want {
		t.Fatalf("Anthropic-Beta = %q, want %q", got, want)
	}
	if strings.Count(got, "context-management-2025-06-27") != 1 {
		t.Fatalf("Anthropic-Beta should de-duplicate official beta, got %q", got)
	}
}

func TestNormalizeClaudeUpstreamModelStripsContext1MSuffix(t *testing.T) {
	tests := map[string]string{
		"claude-opus-4-8[1m]":       "claude-opus-4-8",
		"claude-opus-4-8[1m](high)": "claude-opus-4-8(high)",
		"claude-opus-4-8":           "claude-opus-4-8",
		"":                          "",
	}
	for input, want := range tests {
		if got := normalizeClaudeUpstreamModel(input); got != want {
			t.Fatalf("normalizeClaudeUpstreamModel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestApplyClaudeHeaders_SyntheticOAuthContext1MBetaOrder(t *testing.T) {
	resetClaudeDeviceProfileCache()

	incoming := http.Header{"User-Agent": {"third-party-client/1.0"}}
	req := newClaudeHeaderTestRequest(t, incoming)
	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{
		"access_token": "sk-ant-oat-test",
		"auth_kind":    "oauth",
	}}
	body := []byte(`{"model":"claude-opus-4-8","output_config":{"effort":"high"}}`)

	if err := applyClaudeHeadersForBodyAndModel(req, auth, "sk-ant-oat-test", true, []string{helps.ClaudeCodeEffortBeta}, &config.Config{}, incoming, body, "claude-opus-4-8[1m]"); err != nil {
		t.Fatalf("applyClaudeHeadersForBodyAndModel() error = %v", err)
	}

	want := "claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,effort-2025-11-24,extended-cache-ttl-2025-04-11"
	if got := req.Header.Get("Anthropic-Beta"); got != want {
		t.Fatalf("Anthropic-Beta = %q, want %q", got, want)
	}
}

func TestApplyClaudeHeaders_TracksHighestClaudeCLIFingerprint(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-upgrade",
		Attributes: map[string]string{
			"api_key": "key-upgrade",
		},
	}

	firstReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(firstReq, auth, "key-upgrade", false, nil, cfg, nil)
	assertClaudeFingerprint(t, firstReq.Header, "claude-cli/2.1.62 (external, cli)", "0.74.0", "v24.3.0", "MacOS", "arm64")

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"lobe-chat/1.0"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, auth, "key-upgrade", false, nil, cfg, nil)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.62 (external, cli)", "0.74.0", "v24.3.0", "MacOS", "arm64")

	higherReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.63 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.75.0"},
		"X-Stainless-Runtime-Version": []string{"v24.4.0"},
		"X-Stainless-Os":              []string{"MacOS"},
		"X-Stainless-Arch":            []string{"arm64"},
	})
	applyClaudeHeaders(higherReq, auth, "key-upgrade", false, nil, cfg, nil)
	assertClaudeFingerprint(t, higherReq.Header, "claude-cli/2.1.63 (external, cli)", "0.75.0", "v24.4.0", "MacOS", "arm64")

	lowerReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.61 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.73.0"},
		"X-Stainless-Runtime-Version": []string{"v24.2.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(lowerReq, auth, "key-upgrade", false, nil, cfg, nil)
	assertClaudeFingerprint(t, lowerReq.Header, "claude-cli/2.1.63 (external, cli)", "0.75.0", "v24.4.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_DoesNotDowngradeConfiguredBaselineOnFirstClaudeClient(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-baseline-floor",
		Attributes: map[string]string{
			"api_key": "key-baseline-floor",
		},
	}

	olderClaudeReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(olderClaudeReq, auth, "key-baseline-floor", false, nil, cfg, nil)
	assertClaudeFingerprint(t, olderClaudeReq.Header, "claude-cli/2.1.70 (external, cli)", "0.80.0", "v24.5.0", "MacOS", "arm64")

	newerClaudeReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.71 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.81.0"},
		"X-Stainless-Runtime-Version": []string{"v24.6.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(newerClaudeReq, auth, "key-baseline-floor", false, nil, cfg, nil)
	assertClaudeFingerprint(t, newerClaudeReq.Header, "claude-cli/2.1.71 (external, cli)", "0.81.0", "v24.6.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_UpgradesCachedSoftwareFingerprintWhenBaselineAdvances(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	oldCfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	newCfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.77 (external, cli)",
			PackageVersion:         "0.87.0",
			RuntimeVersion:         "v24.8.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-baseline-reload",
		Attributes: map[string]string{
			"api_key": "key-baseline-reload",
		},
	}

	officialReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.71 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.81.0"},
		"X-Stainless-Runtime-Version": []string{"v24.6.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(officialReq, auth, "key-baseline-reload", false, nil, oldCfg, nil)
	assertClaudeFingerprint(t, officialReq.Header, "claude-cli/2.1.71 (external, cli)", "0.81.0", "v24.6.0", "MacOS", "arm64")

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, auth, "key-baseline-reload", false, nil, newCfg, nil)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.77 (external, cli)", "0.87.0", "v24.8.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_LearnsOfficialFingerprintAfterCustomBaselineFallback(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "my-gateway/1.0",
			PackageVersion:         "custom-pkg",
			RuntimeVersion:         "custom-runtime",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-custom-baseline-learning",
		Attributes: map[string]string{
			"api_key": "key-custom-baseline-learning",
		},
	}

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, auth, "key-custom-baseline-learning", false, nil, cfg, nil)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "my-gateway/1.0", "custom-pkg", "custom-runtime", "MacOS", "arm64")

	officialReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.77 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.87.0"},
		"X-Stainless-Runtime-Version": []string{"v24.8.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(officialReq, auth, "key-custom-baseline-learning", false, nil, cfg, nil)
	assertClaudeFingerprint(t, officialReq.Header, "claude-cli/2.1.77 (external, cli)", "0.87.0", "v24.8.0", "MacOS", "arm64")

	postLearningThirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(postLearningThirdPartyReq, auth, "key-custom-baseline-learning", false, nil, cfg, nil)
	assertClaudeFingerprint(t, postLearningThirdPartyReq.Header, "claude-cli/2.1.77 (external, cli)", "0.87.0", "v24.8.0", "MacOS", "arm64")
}

func TestResolveClaudeDeviceProfile_RechecksCacheBeforeStoringCandidate(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-racy-upgrade",
		Attributes: map[string]string{
			"api_key": "key-racy-upgrade",
		},
	}

	lowPaused := make(chan struct{})
	releaseLow := make(chan struct{})
	var pauseOnce sync.Once
	var releaseOnce sync.Once

	helps.ClaudeDeviceProfileBeforeCandidateStore = func(candidate helps.ClaudeDeviceProfile) {
		if candidate.UserAgent != "claude-cli/2.1.62 (external, cli)" {
			return
		}
		pauseOnce.Do(func() { close(lowPaused) })
		<-releaseLow
	}
	t.Cleanup(func() {
		helps.ClaudeDeviceProfileBeforeCandidateStore = nil
		releaseOnce.Do(func() { close(releaseLow) })
	})

	lowResultCh := make(chan helps.ClaudeDeviceProfile, 1)
	go func() {
		lowResultCh <- helps.ResolveClaudeDeviceProfile(auth, "key-racy-upgrade", http.Header{
			"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
			"X-Stainless-Package-Version": []string{"0.74.0"},
			"X-Stainless-Runtime-Version": []string{"v24.3.0"},
			"X-Stainless-Os":              []string{"Linux"},
			"X-Stainless-Arch":            []string{"x64"},
		}, cfg)
	}()

	select {
	case <-lowPaused:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for lower candidate to pause before storing")
	}

	highResult := helps.ResolveClaudeDeviceProfile(auth, "key-racy-upgrade", http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.63 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.75.0"},
		"X-Stainless-Runtime-Version": []string{"v24.4.0"},
		"X-Stainless-Os":              []string{"MacOS"},
		"X-Stainless-Arch":            []string{"arm64"},
	}, cfg)
	releaseOnce.Do(func() { close(releaseLow) })

	select {
	case lowResult := <-lowResultCh:
		if lowResult.UserAgent != "claude-cli/2.1.63 (external, cli)" {
			t.Fatalf("lowResult.UserAgent = %q, want %q", lowResult.UserAgent, "claude-cli/2.1.63 (external, cli)")
		}
		if lowResult.PackageVersion != "0.75.0" {
			t.Fatalf("lowResult.PackageVersion = %q, want %q", lowResult.PackageVersion, "0.75.0")
		}
		if lowResult.OS != "MacOS" || lowResult.Arch != "arm64" {
			t.Fatalf("lowResult platform = %s/%s, want %s/%s", lowResult.OS, lowResult.Arch, "MacOS", "arm64")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for lower candidate result")
	}

	if highResult.UserAgent != "claude-cli/2.1.63 (external, cli)" {
		t.Fatalf("highResult.UserAgent = %q, want %q", highResult.UserAgent, "claude-cli/2.1.63 (external, cli)")
	}
	if highResult.OS != "MacOS" || highResult.Arch != "arm64" {
		t.Fatalf("highResult platform = %s/%s, want %s/%s", highResult.OS, highResult.Arch, "MacOS", "arm64")
	}

	cached := helps.ResolveClaudeDeviceProfile(auth, "key-racy-upgrade", http.Header{
		"User-Agent": []string{"curl/8.7.1"},
	}, cfg)
	if cached.UserAgent != "claude-cli/2.1.63 (external, cli)" {
		t.Fatalf("cached.UserAgent = %q, want %q", cached.UserAgent, "claude-cli/2.1.63 (external, cli)")
	}
	if cached.PackageVersion != "0.75.0" {
		t.Fatalf("cached.PackageVersion = %q, want %q", cached.PackageVersion, "0.75.0")
	}
	if cached.OS != "MacOS" || cached.Arch != "arm64" {
		t.Fatalf("cached platform = %s/%s, want %s/%s", cached.OS, cached.Arch, "MacOS", "arm64")
	}
}

func TestApplyClaudeHeaders_ThirdPartyBaselineThenOfficialUpgradeKeepsPinnedPlatform(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-third-party-then-official",
		Attributes: map[string]string{
			"api_key": "key-third-party-then-official",
		},
	}

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, auth, "key-third-party-then-official", false, nil, cfg, nil)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.70 (external, cli)", "0.80.0", "v24.5.0", "MacOS", "arm64")

	officialReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.77 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.87.0"},
		"X-Stainless-Runtime-Version": []string{"v24.8.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(officialReq, auth, "key-third-party-then-official", false, nil, cfg, nil)
	assertClaudeFingerprint(t, officialReq.Header, "claude-cli/2.1.77 (external, cli)", "0.87.0", "v24.8.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_DisableDeviceProfileStabilization(t *testing.T) {
	resetClaudeDeviceProfileCache()

	stabilize := false
	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-disable-stability",
		Attributes: map[string]string{
			"api_key": "key-disable-stability",
		},
	}

	firstReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(firstReq, auth, "key-disable-stability", false, nil, cfg, nil)
	assertClaudeFingerprint(t, firstReq.Header, "claude-cli/2.1.62 (external, cli)", "0.74.0", "v24.3.0", "Linux", "x64")

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"lobe-chat/1.0"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, auth, "key-disable-stability", false, nil, cfg, nil)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.60 (external, cli)", "0.10.0", "v18.0.0", "Windows", "x64")

	lowerReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.61 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.73.0"},
		"X-Stainless-Runtime-Version": []string{"v24.2.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(lowerReq, auth, "key-disable-stability", false, nil, cfg, nil)
	assertClaudeFingerprint(t, lowerReq.Header, "claude-cli/2.1.61 (external, cli)", "0.73.0", "v24.2.0", "Windows", "x64")
}

func TestApplyClaudeHeaders_LegacyModePreservesConfiguredUserAgentOverrideForClaudeClients(t *testing.T) {
	resetClaudeDeviceProfileCache()

	stabilize := false
	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-legacy-ua-override",
		Attributes: map[string]string{
			"api_key":           "key-legacy-ua-override",
			"header:User-Agent": "config-ua/1.0",
		},
	}

	req := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(req, auth, "key-legacy-ua-override", false, nil, cfg, nil)

	assertClaudeFingerprint(t, req.Header, "config-ua/1.0", "0.74.0", "v24.3.0", "Linux", "x64")
}

func TestApplyClaudeHeaders_LegacyModeFallsBackToRuntimeOSArchWhenMissing(t *testing.T) {
	resetClaudeDeviceProfileCache()

	stabilize := false
	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-legacy-runtime-os-arch",
		Attributes: map[string]string{
			"api_key": "key-legacy-runtime-os-arch",
		},
	}

	req := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent": []string{"curl/8.7.1"},
	})
	applyClaudeHeaders(req, auth, "key-legacy-runtime-os-arch", false, nil, cfg, nil)

	assertClaudeFingerprint(t, req.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", helps.MapStainlessOS(), helps.MapStainlessArch())
}

func TestApplyClaudeHeaders_UnsetStabilizationAlsoUsesLegacyRuntimeOSArchFallback(t *testing.T) {
	resetClaudeDeviceProfileCache()

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:      "claude-cli/2.1.60 (external, cli)",
			PackageVersion: "0.70.0",
			RuntimeVersion: "v22.0.0",
			OS:             "MacOS",
			Arch:           "arm64",
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-unset-runtime-os-arch",
		Attributes: map[string]string{
			"api_key": "key-unset-runtime-os-arch",
		},
	}

	req := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent": []string{"curl/8.7.1"},
	})
	applyClaudeHeaders(req, auth, "key-unset-runtime-os-arch", false, nil, cfg, nil)

	assertClaudeFingerprint(t, req.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", helps.MapStainlessOS(), helps.MapStainlessArch())
}

func TestClaudeDeviceProfileStabilizationEnabled_DefaultFalse(t *testing.T) {
	if helps.ClaudeDeviceProfileStabilizationEnabled(nil) {
		t.Fatal("expected nil config to default to disabled stabilization")
	}
	if helps.ClaudeDeviceProfileStabilizationEnabled(&config.Config{}) {
		t.Fatal("expected unset stabilize-device-profile to default to disabled stabilization")
	}
}

func TestApplyClaudeToolPrefix(t *testing.T) {
	input := []byte(`{"tools":[{"name":"alpha"},{"name":"proxy_bravo"}],"tool_choice":{"type":"tool","name":"charlie"},"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"delta","id":"t1","input":{}}]}]}`)
	out := applyClaudeToolPrefix(input, "proxy_")

	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "proxy_alpha" {
		t.Fatalf("tools.0.name = %q, want %q", got, "proxy_alpha")
	}
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != "proxy_bravo" {
		t.Fatalf("tools.1.name = %q, want %q", got, "proxy_bravo")
	}
	if got := gjson.GetBytes(out, "tool_choice.name").String(); got != "proxy_charlie" {
		t.Fatalf("tool_choice.name = %q, want %q", got, "proxy_charlie")
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.name").String(); got != "proxy_delta" {
		t.Fatalf("messages.0.content.0.name = %q, want %q", got, "proxy_delta")
	}
}

func TestApplyClaudeToolPrefix_WithToolReference(t *testing.T) {
	input := []byte(`{"tools":[{"name":"alpha"}],"messages":[{"role":"user","content":[{"type":"tool_reference","tool_name":"beta"},{"type":"tool_reference","tool_name":"proxy_gamma"}]}]}`)
	out := applyClaudeToolPrefix(input, "proxy_")

	if got := gjson.GetBytes(out, "messages.0.content.0.tool_name").String(); got != "proxy_beta" {
		t.Fatalf("messages.0.content.0.tool_name = %q, want %q", got, "proxy_beta")
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.tool_name").String(); got != "proxy_gamma" {
		t.Fatalf("messages.0.content.1.tool_name = %q, want %q", got, "proxy_gamma")
	}
}

func TestSanitizeClaudeWebSearchDomains(t *testing.T) {
	// Mirrors the litellm payload from issue #2681: a non-empty allowed_domains
	// alongside an empty blocked_domains, which Anthropic rejects as ambiguous.
	input := []byte(`{"tools":[{"type":"web_search_20250305","name":"web_search","allowed_domains":["anthropic.com"],"blocked_domains":[],"max_uses":8}]}`)
	out := sanitizeClaudeWebSearchDomains(input)

	if gjson.GetBytes(out, "tools.0.blocked_domains").Exists() {
		t.Fatalf("empty blocked_domains should be removed: %s", string(out))
	}
	if got := gjson.GetBytes(out, "tools.0.allowed_domains").Array(); len(got) != 1 || got[0].String() != "anthropic.com" {
		t.Fatalf("non-empty allowed_domains should be preserved: %s", string(out))
	}
	if got := gjson.GetBytes(out, "tools.0.max_uses").Int(); got != 8 {
		t.Fatalf("max_uses should be preserved: got %d", got)
	}
}

func TestSanitizeClaudeWebSearchDomains_LeavesNonBuiltinAndNonEmpty(t *testing.T) {
	// Empty arrays on non-web_search tools must be left untouched.
	input := []byte(`{"tools":[{"type":"custom","name":"x","blocked_domains":[]},{"type":"web_search_20250305","name":"web_search","blocked_domains":["evil.com"]}]}`)
	out := sanitizeClaudeWebSearchDomains(input)

	if !gjson.GetBytes(out, "tools.0.blocked_domains").Exists() {
		t.Fatalf("non-web_search tool fields should be untouched: %s", string(out))
	}
	if got := gjson.GetBytes(out, "tools.1.blocked_domains").Array(); len(got) != 1 || got[0].String() != "evil.com" {
		t.Fatalf("non-empty blocked_domains should be preserved: %s", string(out))
	}
}

func TestApplyClaudeToolPrefix_SkipsBuiltinTools(t *testing.T) {
	input := []byte(`{"tools":[{"type":"web_search_20250305","name":"web_search"},{"name":"my_custom_tool","input_schema":{"type":"object"}}]}`)
	out := applyClaudeToolPrefix(input, "proxy_")

	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "web_search" {
		t.Fatalf("built-in tool name should not be prefixed: tools.0.name = %q, want %q", got, "web_search")
	}
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != "proxy_my_custom_tool" {
		t.Fatalf("custom tool should be prefixed: tools.1.name = %q, want %q", got, "proxy_my_custom_tool")
	}
}

func TestApplyClaudeToolPrefix_BuiltinToolSkipped(t *testing.T) {
	body := []byte(`{
		"tools": [
			{"type": "web_search_20250305", "name": "web_search", "max_uses": 5},
			{"name": "Read"}
		],
		"messages": [
			{"role": "user", "content": [
				{"type": "tool_use", "name": "web_search", "id": "ws1", "input": {}},
				{"type": "tool_use", "name": "Read", "id": "r1", "input": {}}
			]}
		]
	}`)
	out := applyClaudeToolPrefix(body, "proxy_")

	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "web_search" {
		t.Fatalf("tools.0.name = %q, want %q", got, "web_search")
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.name").String(); got != "web_search" {
		t.Fatalf("messages.0.content.0.name = %q, want %q", got, "web_search")
	}
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != "proxy_Read" {
		t.Fatalf("tools.1.name = %q, want %q", got, "proxy_Read")
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.name").String(); got != "proxy_Read" {
		t.Fatalf("messages.0.content.1.name = %q, want %q", got, "proxy_Read")
	}
}

func TestApplyClaudeToolPrefix_KnownBuiltinInHistoryOnly(t *testing.T) {
	body := []byte(`{
		"tools": [
			{"name": "Read"}
		],
		"messages": [
			{"role": "user", "content": [
				{"type": "tool_use", "name": "web_search", "id": "ws1", "input": {}}
			]}
		]
	}`)
	out := applyClaudeToolPrefix(body, "proxy_")

	if got := gjson.GetBytes(out, "messages.0.content.0.name").String(); got != "web_search" {
		t.Fatalf("messages.0.content.0.name = %q, want %q", got, "web_search")
	}
	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "proxy_Read" {
		t.Fatalf("tools.0.name = %q, want %q", got, "proxy_Read")
	}
}

func TestApplyClaudeToolPrefix_CustomToolsPrefixed(t *testing.T) {
	body := []byte(`{
		"tools": [{"name": "Read"}, {"name": "Write"}],
		"messages": [
			{"role": "user", "content": [
				{"type": "tool_use", "name": "Read", "id": "r1", "input": {}},
				{"type": "tool_use", "name": "Write", "id": "w1", "input": {}}
			]}
		]
	}`)
	out := applyClaudeToolPrefix(body, "proxy_")

	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "proxy_Read" {
		t.Fatalf("tools.0.name = %q, want %q", got, "proxy_Read")
	}
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != "proxy_Write" {
		t.Fatalf("tools.1.name = %q, want %q", got, "proxy_Write")
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.name").String(); got != "proxy_Read" {
		t.Fatalf("messages.0.content.0.name = %q, want %q", got, "proxy_Read")
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.name").String(); got != "proxy_Write" {
		t.Fatalf("messages.0.content.1.name = %q, want %q", got, "proxy_Write")
	}
}

func TestApplyClaudeToolPrefix_ToolChoiceBuiltin(t *testing.T) {
	body := []byte(`{
		"tools": [
			{"type": "web_search_20250305", "name": "web_search"},
			{"name": "Read"}
		],
		"tool_choice": {"type": "tool", "name": "web_search"}
	}`)
	out := applyClaudeToolPrefix(body, "proxy_")

	if got := gjson.GetBytes(out, "tool_choice.name").String(); got != "web_search" {
		t.Fatalf("tool_choice.name = %q, want %q", got, "web_search")
	}
}

func TestApplyClaudeToolPrefix_KnownFallbackBuiltinsRemainUnprefixed(t *testing.T) {
	for _, builtin := range []string{"web_search", "code_execution", "text_editor", "computer"} {
		t.Run(builtin, func(t *testing.T) {
			input := []byte(fmt.Sprintf(`{
				"tools":[{"name":"Read"}],
				"tool_choice":{"type":"tool","name":%q},
				"messages":[{"role":"assistant","content":[{"type":"tool_use","name":%q,"id":"toolu_1","input":{}},{"type":"tool_reference","tool_name":%q},{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"tool_reference","tool_name":%q}]}]}]
			}`, builtin, builtin, builtin, builtin))
			out := applyClaudeToolPrefix(input, "proxy_")

			if got := gjson.GetBytes(out, "tool_choice.name").String(); got != builtin {
				t.Fatalf("tool_choice.name = %q, want %q", got, builtin)
			}
			if got := gjson.GetBytes(out, "messages.0.content.0.name").String(); got != builtin {
				t.Fatalf("messages.0.content.0.name = %q, want %q", got, builtin)
			}
			if got := gjson.GetBytes(out, "messages.0.content.1.tool_name").String(); got != builtin {
				t.Fatalf("messages.0.content.1.tool_name = %q, want %q", got, builtin)
			}
			if got := gjson.GetBytes(out, "messages.0.content.2.content.0.tool_name").String(); got != builtin {
				t.Fatalf("messages.0.content.2.content.0.tool_name = %q, want %q", got, builtin)
			}
			if got := gjson.GetBytes(out, "tools.0.name").String(); got != "proxy_Read" {
				t.Fatalf("tools.0.name = %q, want %q", got, "proxy_Read")
			}
		})
	}
}

func TestStripClaudeToolPrefixFromResponse(t *testing.T) {
	input := []byte(`{"content":[{"type":"tool_use","name":"proxy_alpha","id":"t1","input":{}},{"type":"tool_use","name":"bravo","id":"t2","input":{}}]}`)
	out := stripClaudeToolPrefixFromResponse(input, "proxy_")

	if got := gjson.GetBytes(out, "content.0.name").String(); got != "alpha" {
		t.Fatalf("content.0.name = %q, want %q", got, "alpha")
	}
	if got := gjson.GetBytes(out, "content.1.name").String(); got != "bravo" {
		t.Fatalf("content.1.name = %q, want %q", got, "bravo")
	}
}

func TestStripClaudeToolPrefixFromResponse_WithToolReference(t *testing.T) {
	input := []byte(`{"content":[{"type":"tool_reference","tool_name":"proxy_alpha"},{"type":"tool_reference","tool_name":"bravo"}]}`)
	out := stripClaudeToolPrefixFromResponse(input, "proxy_")

	if got := gjson.GetBytes(out, "content.0.tool_name").String(); got != "alpha" {
		t.Fatalf("content.0.tool_name = %q, want %q", got, "alpha")
	}
	if got := gjson.GetBytes(out, "content.1.tool_name").String(); got != "bravo" {
		t.Fatalf("content.1.tool_name = %q, want %q", got, "bravo")
	}
}

func TestStripClaudeToolPrefixFromStreamLine(t *testing.T) {
	line := []byte(`data: {"type":"content_block_start","content_block":{"type":"tool_use","name":"proxy_alpha","id":"t1"},"index":0}`)
	out := stripClaudeToolPrefixFromStreamLine(line, "proxy_")

	payload := bytes.TrimSpace(out)
	if bytes.HasPrefix(payload, []byte("data:")) {
		payload = bytes.TrimSpace(payload[len("data:"):])
	}
	if got := gjson.GetBytes(payload, "content_block.name").String(); got != "alpha" {
		t.Fatalf("content_block.name = %q, want %q", got, "alpha")
	}
}

func TestStripClaudeToolPrefixFromStreamLine_WithToolReference(t *testing.T) {
	line := []byte(`data: {"type":"content_block_start","content_block":{"type":"tool_reference","tool_name":"proxy_beta"},"index":0}`)
	out := stripClaudeToolPrefixFromStreamLine(line, "proxy_")

	payload := bytes.TrimSpace(out)
	if bytes.HasPrefix(payload, []byte("data:")) {
		payload = bytes.TrimSpace(payload[len("data:"):])
	}
	if got := gjson.GetBytes(payload, "content_block.tool_name").String(); got != "beta" {
		t.Fatalf("content_block.tool_name = %q, want %q", got, "beta")
	}
}

func TestApplyClaudeToolPrefix_NestedToolReference(t *testing.T) {
	input := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_123","content":[{"type":"tool_reference","tool_name":"mcp__nia__manage_resource"}]}]}]}`)
	out := applyClaudeToolPrefix(input, "proxy_")
	got := gjson.GetBytes(out, "messages.0.content.0.content.0.tool_name").String()
	if got != "proxy_mcp__nia__manage_resource" {
		t.Fatalf("nested tool_reference tool_name = %q, want %q", got, "proxy_mcp__nia__manage_resource")
	}
}

func TestClaudeExecutor_ExecuteStripsOpenAIEncryptedThinkingBeforeUpstream(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{
		"messages": [
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"codex reasoning","signature":"gAAAAABopenai-encrypted-content"},
				{"type":"text","text":"Answer"}
			]},
			{"role":"user","content":[{"type":"text","text":"next"}]}
		]
	}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if strings.Contains(string(seenBody), "gAAAAABopenai-encrypted-content") || strings.Contains(string(seenBody), "codex reasoning") {
		t.Fatalf("invalid thinking block was forwarded: %s", string(seenBody))
	}
	content := gjson.GetBytes(seenBody, "messages.0.content").Array()
	if len(content) != 1 {
		t.Fatalf("messages.0.content length = %d, want 1: %s", len(content), string(seenBody))
	}
	if got := content[0].Get("text").String(); got != "Answer" {
		t.Fatalf("remaining content text = %q, want Answer", got)
	}
}

func TestClaudeExecutor_ExecuteStripsForeignToolUseSignaturesBeforeUpstream(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{
		"messages": [
			{"role":"assistant","content":[
				{
					"type":"tool_use",
					"id":"toolu_1",
					"name":"lookup",
					"input":{"q":"x"},
					"signature":"skip_thought_signature_validator",
					"thought_signature":"skip_thought_signature_validator",
					"extra_content":{"google":{"thought_signature":"skip_thought_signature_validator"}}
				}
			]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"ok"}]}
		]
	}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	toolUse := gjson.GetBytes(seenBody, "messages.0.content.0")
	if !toolUse.Get("type").Exists() || toolUse.Get("type").String() != "tool_use" {
		t.Fatalf("tool_use block was not preserved: %s", string(seenBody))
	}
	for _, path := range []string{"signature", "thought_signature", "extra_content"} {
		if toolUse.Get(path).Exists() {
			t.Fatalf("foreign tool_use signature field %s was forwarded: %s", path, string(seenBody))
		}
	}
}

func TestShouldSanitizeClaudeMessagesForUpstream_OnlyClaudeFamily(t *testing.T) {
	cases := []struct {
		model string
		want  bool
	}{
		{model: "claude-sonnet-4-5", want: true},
		{model: "claude-3-5-sonnet-20241022", want: true},
		{model: "kimi-k2.5", want: false},
		{model: "mimo-v2", want: false},
		{model: "gemini-3.5-flash", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.model, func(t *testing.T) {
			got := shouldSanitizeClaudeMessagesForUpstream(tc.model)
			if got != tc.want {
				t.Errorf("shouldSanitizeClaudeMessagesForUpstream(%q) = %v, want %v", tc.model, got, tc.want)
			}
		})
	}
}

func TestSanitizeClaudeMessagesForClaudeUpstream_BypassesUnknownModelSignatureMatrix(t *testing.T) {
	rawSignature := "skip_thought_signature_validator"
	body := []byte(`{
		"model": "kimi-k2.5",
		"messages": [
			{
				"role": "assistant",
				"content": [
					{"type": "thinking", "thinking": "keep", "signature": "` + rawSignature + `"},
					{"type": "text", "text": "hello"},
					{"type": "tool_use", "id": "call_123", "name": "get_weather", "input": {}, "signature": "` + rawSignature + `"}
				]
			}
		]
	}`)

	output := sanitizeClaudeMessagesForClaudeUpstreamWithDebug(context.Background(), body, "kimi-k2.5")
	parts := gjson.GetBytes(output, "messages.0.content").Array()
	if len(parts) != 3 {
		t.Fatalf("content length = %d, want 3 when sanitizer is bypassed: %s", len(parts), output)
	}
	if got := parts[0].Get("signature").String(); got != rawSignature {
		t.Fatalf("thinking signature = %q, want preserved %q", got, rawSignature)
	}
	if got := parts[2].Get("signature").String(); got != rawSignature {
		t.Fatalf("tool_use signature = %q, want preserved %q", got, rawSignature)
	}
}

func TestClaudeExecutor_ExecuteBypassesSignatureSanitizerForUnknownModel(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"mimo-v2","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{
		"messages": [
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"keep reasoning","signature":""},
				{"type":"text","text":"Answer"}
			]},
			{"role":"user","content":[{"type":"text","text":"next"}]}
		]
	}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "mimo-v2",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if !strings.Contains(string(seenBody), "keep reasoning") {
		t.Fatalf("unknown-model thinking block should bypass Claude sanitizer: %s", string(seenBody))
	}
}

func TestClaudeExecutor_ExecuteStripsMalformedEPrefixThinkingBeforeUpstream(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	malformedSignature := malformedClaudeTreeSignatureForClaudeExecutorTest()
	payload := []byte(`{
		"messages": [
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"bad reasoning","signature":"` + malformedSignature + `"},
				{"type":"text","text":"Answer"}
			]},
			{"role":"user","content":[{"type":"text","text":"next"}]}
		]
	}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if strings.Contains(string(seenBody), malformedSignature) || strings.Contains(string(seenBody), "bad reasoning") {
		t.Fatalf("malformed E-prefix thinking block was forwarded: %s", string(seenBody))
	}
	content := gjson.GetBytes(seenBody, "messages.0.content").Array()
	if len(content) != 1 {
		t.Fatalf("messages.0.content length = %d, want 1: %s", len(content), string(seenBody))
	}
	if got := content[0].Get("text").String(); got != "Answer" {
		t.Fatalf("remaining content text = %q, want Answer", got)
	}
}

func TestClaudeExecutor_ExecuteStripsInvalidBase64ThinkingBeforeUpstream(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{
		"messages": [
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"bad reasoning","signature":"E!!!invalid!!!"},
				{"type":"text","text":"Answer"}
			]},
			{"role":"user","content":[{"type":"text","text":"next"}]}
		]
	}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if strings.Contains(string(seenBody), "E!!!invalid!!!") || strings.Contains(string(seenBody), "bad reasoning") {
		t.Fatalf("invalid-base64 thinking block was forwarded: %s", string(seenBody))
	}
	content := gjson.GetBytes(seenBody, "messages.0.content").Array()
	if len(content) != 1 {
		t.Fatalf("messages.0.content length = %d, want 1: %s", len(content), string(seenBody))
	}
}

func TestClaudeExecutor_ExecuteStripsEmptySignatureEmptyTextThinking(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{
		"messages": [
			{"role":"assistant","content":[
				{"type":"thinking","text":"","signature":""},
				{"type":"text","text":"Answer"}
			]},
			{"role":"user","content":[{"type":"text","text":"next"}]}
		]
	}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	content := gjson.GetBytes(seenBody, "messages.0.content").Array()
	if len(content) != 1 {
		t.Fatalf("messages.0.content length = %d, want 1: %s", len(content), string(seenBody))
	}
	if got := content[0].Get("type").String(); got != "text" {
		t.Fatalf("remaining content type = %q, want text: %s", got, string(seenBody))
	}
	if got := content[0].Get("text").String(); got != "Answer" {
		t.Fatalf("remaining content text = %q, want Answer: %s", got, string(seenBody))
	}
}

func TestClaudeExecutor_ExecuteStreamStripsOpenAIEncryptedThinkingBeforeUpstream(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"message_stop\"}\n\n"))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{
		"messages": [
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"codex reasoning","signature":"gAAAAABopenai-encrypted-content"},
				{"type":"text","text":"Answer"}
			]},
			{"role":"user","content":[{"type":"text","text":"next"}]}
		]
	}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("ExecuteStream() error = %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("unexpected chunk error: %v", chunk.Err)
		}
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if strings.Contains(string(seenBody), "gAAAAABopenai-encrypted-content") || strings.Contains(string(seenBody), "codex reasoning") {
		t.Fatalf("invalid thinking block was forwarded: %s", string(seenBody))
	}
}

func TestClaudeExecutor_ExecuteStreamDirectPassthroughEmitsCompleteSSEEvents(t *testing.T) {
	firstData := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`
	secondData := `{"type":"message_stop"}`
	upstreamStream := "event: content_block_delta\n" +
		"data: " + firstData + "\n" +
		"\n" +
		"event: message_stop\n" +
		"data: " + secondData + "\n" +
		"\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(upstreamStream))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("ExecuteStream() error = %v", err)
	}

	var payloads []string
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("unexpected chunk error: %v", chunk.Err)
		}
		payloads = append(payloads, string(chunk.Payload))
	}

	want := []string{
		"event: content_block_delta\n" + "data: " + firstData + "\n\n",
		"event: message_stop\n" + "data: " + secondData + "\n\n",
	}
	if len(payloads) != len(want) {
		t.Fatalf("payload count = %d, want %d: %#v", len(payloads), len(want), payloads)
	}
	for i := range want {
		if payloads[i] != want[i] {
			t.Fatalf("payload[%d] = %q, want %q", i, payloads[i], want[i])
		}
	}
}

func TestClaudeExecutor_CountTokensStripsOpenAIEncryptedThinkingBeforeUpstream(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"input_tokens":42}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{
		"messages": [
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"codex reasoning","signature":"gAAAAABopenai-encrypted-content"},
				{"type":"text","text":"Answer"}
			]},
			{"role":"user","content":[{"type":"text","text":"next"}]}
		]
	}`)

	_, err := executor.CountTokens(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("CountTokens() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if strings.Contains(string(seenBody), "gAAAAABopenai-encrypted-content") || strings.Contains(string(seenBody), "codex reasoning") {
		t.Fatalf("invalid thinking block was forwarded: %s", string(seenBody))
	}
}

func TestClaudeExecutor_ReusesUserIDAcrossModelsWhenCacheEnabled(t *testing.T) {
	var userIDs []string
	var requestModels []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		userID := gjson.GetBytes(body, "metadata.user_id").String()
		model := gjson.GetBytes(body, "model").String()
		userIDs = append(userIDs, userID)
		requestModels = append(requestModels, model)
		t.Logf("HTTP Server received request: model=%s, user_id=%s, url=%s", model, userID, r.URL.String())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	t.Logf("End-to-end test: Fake HTTP server started at %s", server.URL)

	cacheEnabled := true
	executor := NewClaudeExecutor(&config.Config{
		ClaudeKey: []config.ClaudeKey{
			{
				APIKey:  "key-123",
				BaseURL: server.URL,
				Cloak: &config.CloakConfig{
					CacheUserID: &cacheEnabled,
				},
			},
		},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}

	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)
	models := []string{"claude-3-5-sonnet", "claude-3-5-haiku"}
	for _, model := range models {
		t.Logf("Sending request for model: %s", model)
		modelPayload, _ := sjson.SetBytes(payload, "model", model)
		if _, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
			Model:   model,
			Payload: modelPayload,
		}, cliproxyexecutor.Options{
			SourceFormat: sdktranslator.FromString("claude"),
			Metadata: map[string]any{
				cliproxyexecutor.ExecutionSessionMetadataKey: "cached-user-id-across-models",
			},
		}); err != nil {
			t.Fatalf("Execute(%s) error: %v", model, err)
		}
	}

	if len(userIDs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(userIDs))
	}
	if userIDs[0] == "" || userIDs[1] == "" {
		t.Fatal("expected user_id to be populated")
	}
	t.Logf("user_id[0] (model=%s): %s", requestModels[0], userIDs[0])
	t.Logf("user_id[1] (model=%s): %s", requestModels[1], userIDs[1])
	if userIDs[0] != userIDs[1] {
		t.Fatalf("expected user_id to be reused across models, got %q and %q", userIDs[0], userIDs[1])
	}
	if !helps.IsValidUserID(userIDs[0]) {
		t.Fatalf("user_id %q is not valid", userIDs[0])
	}
	assertClaudeCodeMetadataUserID(t, userIDs[0])
	t.Logf("✓ End-to-end test passed: Same user_id (%s) was used for both models", userIDs[0])
}

func TestClaudeExecutor_ReusesUserIDByDefault(t *testing.T) {
	var userIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		userIDs = append(userIDs, gjson.GetBytes(body, "metadata.user_id").String())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-default-cache",
		"base_url": server.URL,
	}}

	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	for i := 0; i < 2; i++ {
		if _, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet",
			Payload: payload,
		}, cliproxyexecutor.Options{
			SourceFormat: sdktranslator.FromString("claude"),
			Metadata: map[string]any{
				cliproxyexecutor.ExecutionSessionMetadataKey: "cached-user-id-default",
			},
		}); err != nil {
			t.Fatalf("Execute call %d error: %v", i, err)
		}
	}

	if len(userIDs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(userIDs))
	}
	if userIDs[0] == "" || userIDs[1] == "" {
		t.Fatal("expected user_id to be populated")
	}
	if userIDs[0] != userIDs[1] {
		t.Fatalf("expected user_id to be reused by default, got %q and %q", userIDs[0], userIDs[1])
	}
	assertClaudeCodeMetadataUserID(t, userIDs[0])
}

func TestClaudeExecutor_GeneratesNewUserIDWhenCacheDisabled(t *testing.T) {
	var userIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		userIDs = append(userIDs, gjson.GetBytes(body, "metadata.user_id").String())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":             "key-cache-disabled",
		"base_url":            server.URL,
		"cloak_cache_user_id": "false",
	}}

	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	for i := 0; i < 2; i++ {
		if _, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet",
			Payload: payload,
		}, cliproxyexecutor.Options{
			SourceFormat: sdktranslator.FromString("claude"),
		}); err != nil {
			t.Fatalf("Execute call %d error: %v", i, err)
		}
	}

	if len(userIDs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(userIDs))
	}
	if userIDs[0] == "" || userIDs[1] == "" {
		t.Fatal("expected user_id to be populated")
	}
	if userIDs[0] == userIDs[1] {
		t.Fatalf("expected user_id to change when caching is not enabled, got identical values %q", userIDs[0])
	}
	if !helps.IsValidUserID(userIDs[0]) || !helps.IsValidUserID(userIDs[1]) {
		t.Fatalf("user_ids should be valid, got %q and %q", userIDs[0], userIDs[1])
	}
	assertClaudeCodeMetadataUserID(t, userIDs[0])
	assertClaudeCodeMetadataUserID(t, userIDs[1])
}

func TestSetClaudeRequestModelNormalizesJSONTypeWithoutRewritingCanonicalString(t *testing.T) {
	canonical := []byte(`{"model":"123","messages":[]}`)
	got := setClaudeRequestModel(canonical, "123")
	if len(got) == 0 || &got[0] != &canonical[0] {
		t.Fatal("canonical string model should reuse the original payload")
	}

	for _, input := range []string{
		`{"model":123,"messages":[]}`,
		`{"model":true,"messages":[]}`,
		`{"messages":[]}`,
	} {
		out := setClaudeRequestModel([]byte(input), "123")
		model := gjson.GetBytes(out, "model")
		if model.Type != gjson.String || model.String() != "123" {
			t.Fatalf("setClaudeRequestModel(%s) model = %s (%v), want JSON string 123; output=%s", input, model.Raw, model.Type, out)
		}
	}
}

func TestAggregateClaudeMessageStreamRestoresAndAccumulatesAllDeltaTypes(t *testing.T) {
	upstream := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_stream","type":"message","role":"assistant","content":[],"model":"upstream-model","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":11,"output_tokens":0,"cache_read_input_tokens":3}}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":"","citations":null}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello "}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world"}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"citations_delta","citation":{"type":"web_search_result_location","url":"https://example.com","title":"Example","cited_text":"world"}}}`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"thinking","thinking":"","signature":""}}`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"thinking_delta","thinking":"reason "}}`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"thinking_delta","thinking":"carefully"}}`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"signature_delta","signature":"sig-final"}}`,
		`data: {"type":"content_block_stop","index":1}`,
		``,
		`data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}`,
		`data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"command\":"}}`,
		`data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"\"pwd\"}"}}`,
		`data: {"type":"content_block_stop","index":2}`,
		``,
		`data: {"type":"content_block_start","index":3,"content_block":{"type":"server_tool_use","id":"srv_1","name":"web_search","caller":{"type":"direct"},"input":{}}}`,
		`data: {"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":"{\"query\":\"sdk\"}"}}`,
		`data: {"type":"content_block_stop","index":3}`,
		``,
		`data: {"type":"content_block_start","index":4,"content_block":{"type":"compaction","content":null,"encrypted_content":null}}`,
		`data: {"type":"content_block_delta","index":4,"delta":{"type":"compaction_delta","content":"Earlier conversation summarized.","encrypted_content":"opaque-compaction-payload"}}`,
		`data: {"type":"content_block_stop","index":4}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":9,"cache_creation_input_tokens":2,"server_tool_use":{"web_search_requests":1}},"context_management":{"applied_edits":[{"type":"clear_thinking_20251015","cleared_thinking_turns":2,"cleared_thinking_tokens":128}]}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	executor := &ClaudeExecutor{upstreamModelNormalizer: func(model string) string { return "upstream-model" }}
	message, restored, err := aggregateClaudeMessageStream([]byte(upstream), func(line []byte) []byte {
		line = restoreClaudeOAuthToolNamesFromStreamLine(line, "", false, map[string]string{"Bash": "bash"})
		return executor.restoreResponseModel(line, "claude-sonnet-4-6")
	})
	if err != nil {
		t.Fatalf("aggregateClaudeMessageStream() error = %v", err)
	}

	assertions := map[string]string{
		"id":                          "msg_stream",
		"type":                        "message",
		"role":                        "assistant",
		"model":                       "claude-sonnet-4-6",
		"stop_reason":                 "tool_use",
		"content.0.text":              "hello world",
		"content.0.citations.0.url":   "https://example.com",
		"content.1.thinking":          "reason carefully",
		"content.1.signature":         "sig-final",
		"content.2.name":              "bash",
		"content.2.input.command":     "pwd",
		"content.3.input.query":       "sdk",
		"content.4.content":           "Earlier conversation summarized.",
		"content.4.encrypted_content": "opaque-compaction-payload",
	}
	for path, want := range assertions {
		if got := gjson.GetBytes(message, path).String(); got != want {
			t.Errorf("Message %s = %q, want %q; message=%s", path, got, want, message)
		}
	}
	if got := gjson.GetBytes(message, "usage.input_tokens").Int(); got != 11 {
		t.Errorf("usage.input_tokens = %d, want 11", got)
	}
	if got := gjson.GetBytes(message, "usage.output_tokens").Int(); got != 9 {
		t.Errorf("usage.output_tokens = %d, want 9", got)
	}
	if got := gjson.GetBytes(message, "usage.server_tool_use.web_search_requests").Int(); got != 1 {
		t.Errorf("usage.server_tool_use.web_search_requests = %d, want 1", got)
	}
	if got := gjson.GetBytes(message, "context_management.applied_edits.0.type").String(); got != "clear_thinking_20251015" {
		t.Errorf("context_management.applied_edits type = %q", got)
	}
	if got := gjson.GetBytes(message, "context_management.applied_edits.0.cleared_thinking_tokens").Int(); got != 128 {
		t.Errorf("context_management.applied_edits cleared tokens = %d, want 128", got)
	}
	if !bytes.Contains(restored, []byte(`"model":"claude-sonnet-4-6"`)) {
		t.Fatalf("restored SSE did not restore model: %s", restored)
	}
	if !bytes.Contains(restored, []byte(`"name":"bash"`)) {
		t.Fatalf("restored SSE did not restore OAuth tool name: %s", restored)
	}
}

func TestAggregateClaudeMessageStreamAccumulatesFallbackMCPToolAndMultipleMessageDeltas(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"type":"message_start","message":{"id":"msg_fallback","type":"message","role":"assistant","content":[],"model":"claude-fable-5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":11,"output_tokens":0,"cache_read_input_tokens":2}}}`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"fallback","from":{"model":"claude-fable-5"},"to":{"model":"claude-opus-4-8"},"trigger":{"type":"refusal"}}}`,
		`data: {"type":"content_block_stop","index":0}`,
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"mcp_tool_use","id":"mcptoolu_1","name":"lookup","server_name":"fixture","input":{}}}`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"query\":"}}`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"sdk\"}"}}`,
		`data: {"type":"content_block_stop","index":1}`,
		`data: {"type":"message_delta","delta":{"stop_reason":null,"stop_sequence":null},"usage":{"input_tokens":13,"output_tokens":1,"cache_read_input_tokens":null},"context_management":null}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"input_tokens":null,"output_tokens":3,"cache_read_input_tokens":7,"output_tokens_details":{"thinking_tokens":1}},"context_management":{"applied_edits":[]}}`,
		`data: {"type":"message_stop"}`,
	}, "\n")

	message, _, err := aggregateClaudeMessageStream([]byte(stream), nil)
	if err != nil {
		t.Fatalf("aggregateClaudeMessageStream() error = %v", err)
	}
	assertions := map[string]string{
		"model":                         "claude-opus-4-8",
		"stop_reason":                   "tool_use",
		"content.0.type":                "fallback",
		"content.0.from.model":          "claude-fable-5",
		"content.0.to.model":            "claude-opus-4-8",
		"content.1.type":                "mcp_tool_use",
		"content.1.input.query":         "sdk",
		"usage.input_tokens":            "13",
		"usage.output_tokens":           "3",
		"usage.cache_read_input_tokens": "7",
		"usage.output_tokens_details.thinking_tokens": "1",
	}
	for path, want := range assertions {
		if got := gjson.GetBytes(message, path).String(); got != want {
			t.Errorf("Message %s = %q, want %q; message=%s", path, got, want, message)
		}
	}
	if !gjson.GetBytes(message, "context_management.applied_edits").IsArray() {
		t.Fatalf("latest message_delta context_management was not retained: %s", message)
	}
}

func TestAggregateClaudeMessageStreamRejectsErrorsAndInvalidOrdering(t *testing.T) {
	start := `data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-6","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":0}}}`
	delta := `data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}`
	stop := `data: {"type":"message_stop"}`
	textStart := `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":"","citations":null}}`
	toolStart := `data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}`

	tests := []struct {
		name       string
		stream     string
		wantSubstr string
	}{
		{name: "empty", stream: "", wantSubstr: "empty stream response"},
		{name: "malformed json", stream: `data: {`, wantSubstr: "malformed stream event"},
		{name: "upstream error", stream: `data: {"type":"error","error":{"type":"overloaded_error","message":"busy"}}`, wantSubstr: "busy"},
		{name: "delta before start", stream: textStart, wantSubstr: "before message_start"},
		{name: "event label mismatch", stream: "event: message_stop\n" + start, wantSubstr: "does not match"},
		{name: "duplicate start", stream: strings.Join([]string{start, start}, "\n"), wantSubstr: "before the previous message_stop"},
		{name: "out of order index", stream: strings.Join([]string{start, strings.Replace(textStart, `"index":0`, `"index":1`, 1)}, "\n"), wantSubstr: "out of order"},
		{name: "delta wrong block type", stream: strings.Join([]string{start, textStart, `data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"x"}}`}, "\n"), wantSubstr: "targets text block"},
		{name: "compaction delta wrong block type", stream: strings.Join([]string{start, textStart, `data: {"type":"content_block_delta","index":0,"delta":{"type":"compaction_delta","content":"summary","encrypted_content":"opaque"}}`}, "\n"), wantSubstr: "targets text block"},
		{name: "delta wrong index", stream: strings.Join([]string{start, textStart, `data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"x"}}`}, "\n"), wantSubstr: "has no active content block"},
		{name: "message delta before block stop", stream: strings.Join([]string{start, textStart, delta}, "\n"), wantSubstr: "before content_block_stop"},
		{name: "invalid tool json", stream: strings.Join([]string{start, toolStart, `data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{"}}`, `data: {"type":"content_block_stop","index":0}`}, "\n"), wantSubstr: "invalid JSON"},
		{name: "stop before delta", stream: strings.Join([]string{start, stop}, "\n"), wantSubstr: "before message_delta"},
		{name: "missing stop", stream: strings.Join([]string{start, delta}, "\n"), wantSubstr: "before message_stop"},
		{name: "event after stop", stream: strings.Join([]string{start, delta, stop, delta}, "\n"), wantSubstr: "after message_stop"},
		{name: "done sentinel", stream: `data: [DONE]`, wantSubstr: "non-Anthropic"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := aggregateClaudeMessageStream([]byte(test.stream), nil)
			if err == nil {
				t.Fatal("aggregateClaudeMessageStream() error = nil")
			}
			assertStatusErr(t, err, http.StatusBadGateway)
			if !strings.Contains(err.Error(), test.wantSubstr) {
				t.Fatalf("error = %q, want substring %q", err, test.wantSubstr)
			}
		})
	}
}

func TestAggregateClaudeMessageStreamIgnoresForwardCompatibleEvents(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-6","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":0}}}`,
		`data: {"type":"future_event","future_field":true}`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"future_delta","future_field":true}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}`,
		`data: {"type":"content_block_stop","index":0}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}`,
		`data: {"type":"message_stop"}`,
	}, "\n")
	message, _, err := aggregateClaudeMessageStream([]byte(stream), nil)
	if err != nil {
		t.Fatalf("aggregateClaudeMessageStream() error = %v", err)
	}
	if got := gjson.GetBytes(message, "content.0.text").String(); got != "ok" {
		t.Fatalf("aggregated text = %q, want ok", got)
	}
}

func TestClaudeExecutorExecuteSyntheticFirstPartyOAuthForcesStreamAndAggregatesMessage(t *testing.T) {
	var upstreamBody []byte
	var upstreamHeaders http.Header
	sse := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_oauth","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-6","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":4,"output_tokens":0}}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"pwd\"}"}}`,
		`data: {"type":"content_block_stop","index":0}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":3}}`,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.URL.String(); got != "https://api.anthropic.com/v1/messages?beta=true" {
			t.Fatalf("upstream URL = %q", got)
		}
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatalf("read upstream body: %v", errRead)
		}
		upstreamBody = bytes.Clone(body)
		upstreamHeaders = req.Header.Clone()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader(sse)),
			Request:    req,
		}, nil
	}))

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{
		"access_token": "sk-ant-oat-test",
		"auth_kind":    "oauth",
	}}
	payload := []byte(`{"model":"claude-sonnet-4-6","stream":false,"tools":[{"name":"bash","description":"run","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"Please run pwd and report."}]}`)
	response, errExecute := executor.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      http.Header{"User-Agent": {"third-party-client/1.0"}},
		Metadata: map[string]any{
			cliproxyexecutor.ExecutionSessionMetadataKey: "synthetic-oauth-stream-test",
		},
	})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	if !gjson.GetBytes(upstreamBody, "stream").Bool() {
		t.Fatalf("synthetic first-party OAuth upstream stream = false; body=%s", upstreamBody)
	}
	if got := gjson.GetBytes(upstreamBody, "tools.0.name").String(); got != "Bash" {
		t.Fatalf("upstream tool name = %q, want Bash", got)
	}
	if got := gjson.GetBytes(upstreamBody, "context_management.edits.0.type").String(); got != "clear_thinking_20251015" {
		t.Fatalf("upstream context_management type = %q; body=%s", got, upstreamBody)
	}
	if got := gjson.GetBytes(upstreamBody, "context_management.edits.0.keep").String(); got != "all" {
		t.Fatalf("upstream context_management keep = %q; body=%s", got, upstreamBody)
	}
	if got := gjson.GetBytes(upstreamBody, "thinking").Raw; got != `{"type":"adaptive"}` {
		t.Fatalf("upstream thinking = %s, want captured adaptive shape", got)
	}
	if got := gjson.GetBytes(upstreamBody, "max_tokens").Int(); got != 32000 {
		t.Fatalf("upstream max_tokens = %d, want native Sonnet 4.6 default 32000; body=%s", got, upstreamBody)
	}
	var topLevelKeys []string
	gjson.ParseBytes(upstreamBody).ForEach(func(key, _ gjson.Result) bool {
		topLevelKeys = append(topLevelKeys, key.String())
		return true
	})
	wantTopLevelKeys := []string{"model", "messages", "system", "tools", "metadata", "max_tokens", "thinking", "context_management", "output_config", "stream"}
	if got, want := strings.Join(topLevelKeys, ","), strings.Join(wantTopLevelKeys, ","); got != want {
		t.Fatalf("upstream top-level key order = %q, want captured order %q; body=%s", got, want, upstreamBody)
	}
	if got := claudeCCHFromBody(t, upstreamBody); got == "00000" {
		t.Fatalf("first-party OAuth cch was not signed: %s", upstreamBody)
	}
	if got := upstreamHeaders.Get("User-Agent"); got != helps.OfficialClaudeCodeOAuthProfile().UserAgent {
		t.Fatalf("upstream User-Agent = %q", got)
	}
	if got := response.Headers.Get("Content-Type"); got != "application/json" {
		t.Fatalf("response Content-Type = %q, want application/json", got)
	}
	if got := gjson.GetBytes(response.Payload, "type").String(); got != "message" {
		t.Fatalf("response type = %q, want message; payload=%s", got, response.Payload)
	}
	if got := gjson.GetBytes(response.Payload, "content.0.name").String(); got != "bash" {
		t.Fatalf("response tool name = %q, want restored bash; payload=%s", got, response.Payload)
	}
	if got := gjson.GetBytes(response.Payload, "content.0.input.command").String(); got != "pwd" {
		t.Fatalf("response tool input = %q, want pwd; payload=%s", got, response.Payload)
	}
	if got := gjson.GetBytes(response.Payload, "usage.output_tokens").Int(); got != 3 {
		t.Fatalf("response output_tokens = %d, want 3", got)
	}
}

func TestCanonicalizeSyntheticClaudeCodeBodyOrderMatchesNativeSpreads(t *testing.T) {
	body := []byte(`{
		"stream":true,"output_config":{"effort":"high"},
		"temperature":0.7,"top_p":0.9,"top_k":40,"custom_extra":1,
		"fallback_credit_token":"credit","context_hint":{"type":"x"},
		"messages":[],"model":"claude-sonnet-4-6","cache_control":{"type":"ephemeral"},
		"thinking":{"type":"adaptive"},"fallbacks":[],"metadata":{},"max_tokens":32000
	}`)
	out := canonicalizeSyntheticClaudeCodeBodyOrder(body)
	var keys []string
	gjson.ParseBytes(out).ForEach(func(key, _ gjson.Result) bool {
		keys = append(keys, key.String())
		return true
	})
	want := []string{
		"model", "messages", "metadata", "max_tokens", "thinking",
		"context_hint", "cache_control", "fallbacks",
		"temperature", "top_p", "top_k", "custom_extra",
		"output_config", "fallback_credit_token", "stream",
	}
	if got := strings.Join(keys, ","); got != strings.Join(want, ",") {
		t.Fatalf("top-level key order = %q, want %q; body=%s", got, strings.Join(want, ","), out)
	}
	if strings.Contains(string(out), "\n") || strings.Contains(string(out), "\t") {
		t.Fatalf("canonical body retained formatting whitespace: %q", out)
	}
}

func TestClaudeExecutorRealClaudeCodePreservesValidCCH(t *testing.T) {
	unsigned := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=cli; cch=00000;"},{"type":"text","text":"You are Claude Code, Anthropic's official CLI for Claude."}],"max_tokens":32,"stream":false}`)
	signed := mustSignAnthropicMessagesBody(t, unsigned)
	wantBilling := gjson.GetBytes(signed, "system.0.text").String()

	var upstreamBody []byte
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatalf("read upstream body: %v", errRead)
		}
		upstreamBody = bytes.Clone(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(
				`{"id":"msg_real","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"model":"claude-sonnet-4-6","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`,
			)),
			Request: req,
		}, nil
	}))

	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{
		"access_token": "sk-ant-oat-test",
		"auth_kind":    "oauth",
	}}
	_, errExecute := NewClaudeExecutor(&config.Config{}).Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: signed,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      http.Header{"User-Agent": {"claude-cli/2.1.215 (external, cli)"}},
	})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if got := gjson.GetBytes(upstreamBody, "system.0.text").String(); got != wantBilling {
		t.Fatalf("real Claude Code billing block changed:\n got: %q\nwant: %q", got, wantBilling)
	}
	resigned, errResign := resignAnthropicMessagesBody(upstreamBody)
	if errResign != nil {
		t.Fatalf("resignAnthropicMessagesBody() error = %v", errResign)
	}
	if !bytes.Equal(resigned, upstreamBody) {
		t.Fatalf("real Claude Code cch became stale in passthrough\nbody:     %s\nresigned: %s", upstreamBody, resigned)
	}
}

func TestClaudeExecutorExecuteDoesNotForceSyntheticStreamOutsideCloakedFirstPartyOAuth(t *testing.T) {
	tests := []struct {
		name    string
		auth    *cliproxyauth.Auth
		headers http.Header
	}{
		{
			name:    "api key custom base",
			auth:    &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-123"}},
			headers: http.Header{"User-Agent": {"third-party-client/1.0"}},
		},
		{
			name:    "real Claude Code OAuth",
			auth:    &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat-test", "auth_kind": "oauth"}},
			headers: http.Header{"User-Agent": {"claude-cli/2.1.215 (external, cli)"}},
		},
		{
			name:    "OAuth cloak disabled",
			auth:    &cliproxyauth.Auth{Provider: "claude", Attributes: map[string]string{"cloak_mode": "never"}, Metadata: map[string]any{"access_token": "sk-ant-oat-test", "auth_kind": "oauth"}},
			headers: http.Header{"User-Agent": {"third-party-client/1.0"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var upstreamBody []byte
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				body, errRead := io.ReadAll(req.Body)
				if errRead != nil {
					t.Fatalf("read upstream body: %v", errRead)
				}
				upstreamBody = bytes.Clone(body)
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body: io.NopCloser(strings.NewReader(
						`{"id":"msg_json","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"model":"claude-sonnet-4-6","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`,
					)),
					Request: req,
				}, nil
			}))

			auth := test.auth
			if auth.Attributes != nil && auth.Attributes["api_key"] != "" {
				serverURL := "https://custom-anthropic.example"
				auth.Attributes["base_url"] = serverURL
			}
			response, errExecute := NewClaudeExecutor(&config.Config{}).Execute(ctx, auth, cliproxyexecutor.Request{
				Model:   "claude-sonnet-4-6",
				Payload: []byte(`{"model":"claude-sonnet-4-6","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`),
			}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude"), Headers: test.headers})
			if errExecute != nil {
				t.Fatalf("Execute() error = %v", errExecute)
			}
			if gjson.GetBytes(upstreamBody, "stream").Bool() {
				t.Fatalf("upstream stream was forced outside synthetic cloaked first-party OAuth: %s", upstreamBody)
			}
			if got := gjson.GetBytes(response.Payload, "content.0.text").String(); got != "ok" {
				t.Fatalf("response text = %q, want ok", got)
			}
		})
	}
}

func TestClaudeExecutorExecuteStreamForcesFinalUpstreamStreamTrue(t *testing.T) {
	var upstreamBody []byte
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatalf("read upstream body: %v", errRead)
		}
		upstreamBody = bytes.Clone(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader("data: {\"type\":\"message_stop\"}\n\n")),
			Request:    req,
		}, nil
	}))

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-123", "base_url": "https://custom-anthropic.example"}}
	result, errExecute := executor.ExecuteStream(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: []byte(`{"model":"claude-sonnet-4-6","max_tokens":32,"stream":false,"messages":[{"role":"user","content":"hello"}]}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if errExecute != nil {
		t.Fatalf("ExecuteStream() error = %v", errExecute)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error = %v", chunk.Err)
		}
	}
	if !gjson.GetBytes(upstreamBody, "stream").Bool() {
		t.Fatalf("ExecuteStream upstream stream = false; body=%s", upstreamBody)
	}
}

func TestClaudeExecutorExecuteStreamSignsFirstPartyOAuthCCH(t *testing.T) {
	var upstreamBody []byte
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatalf("read upstream body: %v", errRead)
		}
		upstreamBody = bytes.Clone(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader("data: {\"type\":\"message_stop\"}\n\n")),
			Request:    req,
		}, nil
	}))

	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{
		"access_token": "sk-ant-oat-test",
		"auth_kind":    "oauth",
	}}
	result, errExecute := NewClaudeExecutor(&config.Config{}).ExecuteStream(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: []byte(`{"model":"claude-sonnet-4-6","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      http.Header{"User-Agent": {"third-party-client/1.0"}},
	})
	if errExecute != nil {
		t.Fatalf("ExecuteStream() error = %v", errExecute)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error = %v", chunk.Err)
		}
	}
	if got := claudeCCHFromBody(t, upstreamBody); got == "00000" {
		t.Fatalf("first-party OAuth streaming cch was not signed: %s", upstreamBody)
	}
	if got := gjson.GetBytes(upstreamBody, "tools").Raw; got != "[]" {
		t.Fatalf("first-party OAuth streaming tools = %s, want []", got)
	}
	if got := gjson.GetBytes(upstreamBody, "context_management.edits.0.type").String(); got != "clear_thinking_20251015" {
		t.Fatalf("first-party OAuth streaming context_management missing: %s", upstreamBody)
	}
}

func TestClaudeExecutorExecuteStreamStripsContext1MModelAndAddsBeta(t *testing.T) {
	var upstreamBody []byte
	var upstreamHeaders http.Header
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatalf("read upstream body: %v", errRead)
		}
		upstreamBody = bytes.Clone(body)
		upstreamHeaders = req.Header.Clone()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"text/event-stream"}},
			Body: io.NopCloser(strings.NewReader(strings.Join([]string{
				`data: {"type":"message_start","message":{"id":"msg_1m","model":"claude-opus-4-8","content":[],"usage":{"input_tokens":1,"output_tokens":1}}}`,
				`data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}`,
				`data: {"type":"message_stop"}`,
				``,
			}, "\n"))),
			Request: req,
		}, nil
	}))

	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{
		"access_token": "sk-ant-oat-test",
		"auth_kind":    "oauth",
	}}
	result, errExecute := NewClaudeExecutor(&config.Config{}).ExecuteStream(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-opus-4-8[1m]",
		Payload: []byte(`{"model":"claude-opus-4-8[1m]","messages":[{"role":"user","content":"hello"}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      http.Header{"User-Agent": {"third-party-client/1.0"}},
	})
	if errExecute != nil {
		t.Fatalf("ExecuteStream() error = %v", errExecute)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error = %v", chunk.Err)
		}
	}
	if got := gjson.GetBytes(upstreamBody, "model").String(); got != "claude-opus-4-8" {
		t.Fatalf("upstream model = %q, want claude-opus-4-8; body=%s", got, upstreamBody)
	}
	if got := upstreamHeaders.Get("Anthropic-Beta"); !strings.Contains(got, helps.ClaudeCodeContext1MBeta) {
		t.Fatalf("Anthropic-Beta missing %s: %q", helps.ClaudeCodeContext1MBeta, got)
	}
}

func TestClaudeExecutorCountTokensDoesNotInjectMessagesBilling(t *testing.T) {
	var upstreamBody []byte
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.URL.Path; got != "/v1/messages/count_tokens" {
			t.Fatalf("upstream path = %q", got)
		}
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatalf("read upstream body: %v", errRead)
		}
		upstreamBody = bytes.Clone(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"input_tokens":7}`)),
			Request:    req,
		}, nil
	}))

	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{
		"access_token": "sk-ant-oat-test",
		"auth_kind":    "oauth",
	}}
	_, errCount := NewClaudeExecutor(&config.Config{}).CountTokens(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: []byte(`{"model":"claude-sonnet-4-6","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      http.Header{"User-Agent": {"third-party-client/1.0"}},
	})
	if errCount != nil {
		t.Fatalf("CountTokens() error = %v", errCount)
	}
	if gjson.GetBytes(upstreamBody, "system").Exists() {
		t.Fatalf("count_tokens must not synthesize the messages system profile: %s", upstreamBody)
	}
	if got := gjson.GetBytes(upstreamBody, "tools").Raw; got != "[]" {
		t.Fatalf("count_tokens tools = %s, want official empty array", got)
	}
	if gjson.GetBytes(upstreamBody, "context_management").Exists() {
		t.Fatalf("count_tokens must not synthesize context_management: %s", upstreamBody)
	}
}

func TestClaudeExecutor_ExecuteOpenAINonStreamRejectsEmptyClaudeStream(t *testing.T) {
	_, err := executeOpenAIChatCompletionThroughClaude(t, "")
	if err == nil {
		t.Fatal("Execute error = nil, want empty stream error")
	}
	assertStatusErr(t, err, http.StatusBadGateway)
	if !strings.Contains(err.Error(), "empty stream response") {
		t.Fatalf("Execute error = %q, want empty stream response", err.Error())
	}
}

func TestClaudeExecutor_ExecuteOpenAINonStreamRejectsClaudeErrorEvent(t *testing.T) {
	body := `data: {"type":"error","error":{"type":"overloaded_error","message":"upstream overloaded"}}` + "\n"
	_, err := executeOpenAIChatCompletionThroughClaude(t, body)
	if err == nil {
		t.Fatal("Execute error = nil, want upstream error event")
	}
	assertStatusErr(t, err, http.StatusBadGateway)
	if !strings.Contains(err.Error(), "upstream overloaded") {
		t.Fatalf("Execute error = %q, want upstream overloaded", err.Error())
	}
}

func TestClaudeExecutor_ExecuteOpenAINonStreamRejectsIncompleteClaudeStream(t *testing.T) {
	body := strings.Join([]string{
		`data: {"type":"message_start","message":{"id":"msg_123","model":"claude-3-5-sonnet-20241022"}}`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	_, err := executeOpenAIChatCompletionThroughClaude(t, body)
	if err == nil {
		t.Fatal("Execute error = nil, want incomplete stream error")
	}
	assertStatusErr(t, err, http.StatusBadGateway)
	if !strings.Contains(err.Error(), "ended before message completion") {
		t.Fatalf("Execute error = %q, want incomplete stream error", err.Error())
	}
}

func TestClaudeExecutor_ExecuteOpenAINonStreamConvertsValidClaudeStream(t *testing.T) {
	body := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_123","model":"claude-3-5-sonnet-20241022"}}`,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}`,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":2,"output_tokens":1}}`,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	resp, err := executeOpenAIChatCompletionThroughClaude(t, body)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if got := gjson.GetBytes(resp.Payload, "id").String(); got != "msg_123" {
		t.Fatalf("response id = %q, want msg_123; payload=%s", got, string(resp.Payload))
	}
	if got := gjson.GetBytes(resp.Payload, "model").String(); got != "claude-3-5-sonnet-20241022" {
		t.Fatalf("response model = %q, want claude-3-5-sonnet-20241022", got)
	}
	if got := gjson.GetBytes(resp.Payload, "choices.0.message.content").String(); got != "ok" {
		t.Fatalf("response content = %q, want ok", got)
	}
	if got := gjson.GetBytes(resp.Payload, "usage.total_tokens").Int(); got != 3 {
		t.Fatalf("usage.total_tokens = %d, want 3", got)
	}
}

func executeOpenAIChatCompletionThroughClaude(t *testing.T, upstreamBody string) (cliproxyexecutor.Response, error) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"hi"}]}`)

	return executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai"),
	})
}

func assertStatusErr(t *testing.T, err error, want int) {
	t.Helper()

	status, ok := err.(interface{ StatusCode() int })
	if !ok {
		t.Fatalf("error %T does not expose StatusCode", err)
	}
	if got := status.StatusCode(); got != want {
		t.Fatalf("StatusCode() = %d, want %d", got, want)
	}
}

func TestStripClaudeToolPrefixFromResponse_NestedToolReference(t *testing.T) {
	input := []byte(`{"content":[{"type":"tool_result","tool_use_id":"toolu_123","content":[{"type":"tool_reference","tool_name":"proxy_mcp__nia__manage_resource"}]}]}`)
	out := stripClaudeToolPrefixFromResponse(input, "proxy_")
	got := gjson.GetBytes(out, "content.0.content.0.tool_name").String()
	if got != "mcp__nia__manage_resource" {
		t.Fatalf("nested tool_reference tool_name = %q, want %q", got, "mcp__nia__manage_resource")
	}
}

func TestApplyClaudeToolPrefix_NestedToolReferenceWithStringContent(t *testing.T) {
	// tool_result.content can be a string - should not be processed
	input := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_123","content":"plain string result"}]}]}`)
	out := applyClaudeToolPrefix(input, "proxy_")
	got := gjson.GetBytes(out, "messages.0.content.0.content").String()
	if got != "plain string result" {
		t.Fatalf("string content should remain unchanged = %q", got)
	}
}

func TestApplyClaudeToolPrefix_SkipsBuiltinToolReference(t *testing.T) {
	input := []byte(`{"tools":[{"type":"web_search_20250305","name":"web_search"}],"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"tool_reference","tool_name":"web_search"}]}]}]}`)
	out := applyClaudeToolPrefix(input, "proxy_")
	got := gjson.GetBytes(out, "messages.0.content.0.content.0.tool_name").String()
	if got != "web_search" {
		t.Fatalf("built-in tool_reference should not be prefixed, got %q", got)
	}
}

func TestNormalizeCacheControlTTL_DowngradesLaterOneHourBlocks(t *testing.T) {
	payload := []byte(`{
		"tools": [{"name":"t1","cache_control":{"type":"ephemeral","ttl":"1h"}}],
		"system": [{"type":"text","text":"s1","cache_control":{"type":"ephemeral"}}],
		"messages": [{"role":"user","content":[{"type":"text","text":"u1","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]
	}`)

	out := normalizeCacheControlTTL(payload)

	if got := gjson.GetBytes(out, "tools.0.cache_control.ttl").String(); got != "1h" {
		t.Fatalf("tools.0.cache_control.ttl = %q, want %q", got, "1h")
	}
	if gjson.GetBytes(out, "messages.0.content.0.cache_control.ttl").Exists() {
		t.Fatalf("messages.0.content.0.cache_control.ttl should be removed after a default-5m block")
	}
}

func TestNormalizeCacheControlTTL_PreservesOriginalBytesWhenNoChange(t *testing.T) {
	// Payload where no TTL normalization is needed (all blocks use 1h with no
	// preceding 5m block). The text intentionally contains HTML chars (<, >, &)
	// that json.Marshal would escape to \u003c etc., altering byte identity.
	payload := []byte(`{"tools":[{"name":"t1","cache_control":{"type":"ephemeral","ttl":"1h"}}],"system":[{"type":"text","text":"<system-reminder>foo & bar</system-reminder>","cache_control":{"type":"ephemeral","ttl":"1h"}}],"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)

	out := normalizeCacheControlTTL(payload)

	if !bytes.Equal(out, payload) {
		t.Fatalf("normalizeCacheControlTTL altered bytes when no change was needed.\noriginal: %s\ngot:      %s", payload, out)
	}
}

func TestNormalizeCacheControlTTL_PreservesKeyOrderWhenModified(t *testing.T) {
	payload := []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"u1","cache_control":{"type":"ephemeral","ttl":"1h"}}]}],"tools":[{"name":"t1","cache_control":{"type":"ephemeral"}}],"system":[{"type":"text","text":"s1","cache_control":{"type":"ephemeral"}}]}`)

	out := normalizeCacheControlTTL(payload)

	if gjson.GetBytes(out, "messages.0.content.0.cache_control.ttl").Exists() {
		t.Fatalf("messages.0.content.0.cache_control.ttl should be removed after a default-5m block")
	}

	outStr := string(out)
	idxModel := strings.Index(outStr, `"model"`)
	idxMessages := strings.Index(outStr, `"messages"`)
	idxTools := strings.Index(outStr, `"tools"`)
	idxSystem := strings.Index(outStr, `"system"`)
	if idxModel == -1 || idxMessages == -1 || idxTools == -1 || idxSystem == -1 {
		t.Fatalf("failed to locate top-level keys in output: %s", outStr)
	}
	if !(idxModel < idxMessages && idxMessages < idxTools && idxTools < idxSystem) {
		t.Fatalf("top-level key order changed:\noriginal: %s\ngot:      %s", payload, out)
	}
}

func TestEnforceCacheControlLimit_StripsNonLastToolBeforeMessages(t *testing.T) {
	payload := []byte(`{
		"tools": [
			{"name":"t1","cache_control":{"type":"ephemeral"}},
			{"name":"t2","cache_control":{"type":"ephemeral"}}
		],
		"system": [{"type":"text","text":"s1","cache_control":{"type":"ephemeral"}}],
		"messages": [
			{"role":"user","content":[{"type":"text","text":"u1","cache_control":{"type":"ephemeral"}}]},
			{"role":"user","content":[{"type":"text","text":"u2","cache_control":{"type":"ephemeral"}}]}
		]
	}`)

	out := enforceCacheControlLimit(payload, 4)

	if got := countCacheControls(out); got != 4 {
		t.Fatalf("cache_control count = %d, want 4", got)
	}
	if gjson.GetBytes(out, "tools.0.cache_control").Exists() {
		t.Fatalf("tools.0.cache_control should be removed first (non-last tool)")
	}
	if !gjson.GetBytes(out, "tools.1.cache_control").Exists() {
		t.Fatalf("tools.1.cache_control (last tool) should be preserved")
	}
	if !gjson.GetBytes(out, "messages.0.content.0.cache_control").Exists() || !gjson.GetBytes(out, "messages.1.content.0.cache_control").Exists() {
		t.Fatalf("message cache_control blocks should be preserved when non-last tool removal is enough")
	}
}

func TestEnforceCacheControlLimit_PreservesKeyOrderWhenModified(t *testing.T) {
	payload := []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"u1","cache_control":{"type":"ephemeral"}},{"type":"text","text":"u2","cache_control":{"type":"ephemeral"}}]}],"tools":[{"name":"t1","cache_control":{"type":"ephemeral"}},{"name":"t2","cache_control":{"type":"ephemeral"}}],"system":[{"type":"text","text":"s1","cache_control":{"type":"ephemeral"}}]}`)

	out := enforceCacheControlLimit(payload, 4)

	if got := countCacheControls(out); got != 4 {
		t.Fatalf("cache_control count = %d, want 4", got)
	}
	if gjson.GetBytes(out, "tools.0.cache_control").Exists() {
		t.Fatalf("tools.0.cache_control should be removed first (non-last tool)")
	}

	outStr := string(out)
	idxModel := strings.Index(outStr, `"model"`)
	idxMessages := strings.Index(outStr, `"messages"`)
	idxTools := strings.Index(outStr, `"tools"`)
	idxSystem := strings.Index(outStr, `"system"`)
	if idxModel == -1 || idxMessages == -1 || idxTools == -1 || idxSystem == -1 {
		t.Fatalf("failed to locate top-level keys in output: %s", outStr)
	}
	if !(idxModel < idxMessages && idxMessages < idxTools && idxTools < idxSystem) {
		t.Fatalf("top-level key order changed:\noriginal: %s\ngot:      %s", payload, out)
	}
}

func TestEnforceCacheControlLimit_ToolOnlyPayloadStillRespectsLimit(t *testing.T) {
	payload := []byte(`{
		"tools": [
			{"name":"t1","cache_control":{"type":"ephemeral"}},
			{"name":"t2","cache_control":{"type":"ephemeral"}},
			{"name":"t3","cache_control":{"type":"ephemeral"}},
			{"name":"t4","cache_control":{"type":"ephemeral"}},
			{"name":"t5","cache_control":{"type":"ephemeral"}}
		]
	}`)

	out := enforceCacheControlLimit(payload, 4)

	if got := countCacheControls(out); got != 4 {
		t.Fatalf("cache_control count = %d, want 4", got)
	}
	if gjson.GetBytes(out, "tools.0.cache_control").Exists() {
		t.Fatalf("tools.0.cache_control should be removed to satisfy max=4")
	}
	if !gjson.GetBytes(out, "tools.4.cache_control").Exists() {
		t.Fatalf("last tool cache_control should be preserved when possible")
	}
}

func TestEnsureClaudeCodeCurrentUserCacheControl_SkipsSystemReminders(t *testing.T) {
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"<system-reminder>\nctx\n</system-reminder>"},{"type":"text","text":"Reply only OK"}]}]}`)

	out := ensureClaudeCodeCurrentUserCacheControl(payload)

	if gjson.GetBytes(out, "messages.0.content.0.cache_control").Exists() {
		t.Fatalf("system-reminder block should not receive cache_control: %s", string(out))
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("real user prompt cache_control.type = %q, want ephemeral: %s", got, string(out))
	}
}

func TestEnsureClaudeCodeCurrentUserCacheControl_PreservesHistoryAndMarksCurrentPrompt(t *testing.T) {
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"client cached","cache_control":{"type":"ephemeral"}},{"type":"text","text":"Reply only OK"}]}]}`)

	out := ensureClaudeCodeCurrentUserCacheControl(payload)

	if got := gjson.GetBytes(out, "messages.0.content.0.cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("existing cache_control changed: %s", out)
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("current user prompt cache_control.type = %q, want ephemeral: %s", got, out)
	}
}

func TestClaudeExecutor_CountTokens_PreservesExplicitCacheControls(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"input_tokens":42}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}

	payload := []byte(`{
		"tools": [
			{"name":"t1","cache_control":{"type":"ephemeral","ttl":"1h"}},
			{"name":"t2","cache_control":{"type":"ephemeral"}}
		],
		"system": [
			{"type":"text","text":"s1","cache_control":{"type":"ephemeral","ttl":"1h"}},
			{"type":"text","text":"s2","cache_control":{"type":"ephemeral","ttl":"1h"}}
		],
		"messages": [
			{"role":"user","content":[{"type":"text","text":"u1","cache_control":{"type":"ephemeral","ttl":"1h"}}]},
			{"role":"user","content":[{"type":"text","text":"u2","cache_control":{"type":"ephemeral","ttl":"1h"}}]}
		]
	}`)

	_, err := executor.CountTokens(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-haiku-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("CountTokens error: %v", err)
	}

	if len(seenBody) == 0 {
		t.Fatal("expected count_tokens request body to be captured")
	}
	if got := countCacheControls(seenBody); got != 6 {
		t.Fatalf("count_tokens body has %d cache_control blocks, want caller's 6", got)
	}
	if !hasTTLOrderingViolation(seenBody) {
		t.Fatalf("count_tokens rewrote caller cache-control ordering: %s", string(seenBody))
	}
}

func TestClaudeExecutor_ExecuteSanitizesSignaturesBeforeUpstream(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-4-5","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}

	payload := []byte(`{
		"model": "claude-sonnet-4-5",
		"max_tokens": 16,
		"messages": [
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"drop this","signature":""},
				{"type":"text","text":"I will run git status."},
				{"type":"tool_use","id":"Bash-1","name":"Bash","input":{"command":"git status"},"signature":"bad","thoughtSignature":"bad2","model":"claude-opus-4-1"}
			]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"Bash-1","content":"ok"}]}
		]
	}`)

	if _, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-5",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Stream:       false,
	}); err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	parts := gjson.GetBytes(seenBody, "messages.0.content").Array()
	if len(parts) != 2 {
		t.Fatalf("messages.0.content length = %d, want 2; body=%s", len(parts), seenBody)
	}
	if parts[0].Get("type").String() != "text" {
		t.Fatalf("first remaining part = %s, want text", parts[0].Raw)
	}
	toolUse := parts[1]
	if toolUse.Get("type").String() != "tool_use" {
		t.Fatalf("second remaining part = %s, want tool_use", toolUse.Raw)
	}
	for _, path := range []string{"signature", "thoughtSignature", "model"} {
		if toolUse.Get(path).Exists() {
			t.Fatalf("tool_use.%s should be removed before upstream: %s", path, seenBody)
		}
	}
}

func hasTTLOrderingViolation(payload []byte) bool {
	seen5m := false
	violates := false

	checkCC := func(cc gjson.Result) {
		if !cc.Exists() || violates {
			return
		}
		ttl := cc.Get("ttl").String()
		if ttl != "1h" {
			seen5m = true
			return
		}
		if seen5m {
			violates = true
		}
	}

	tools := gjson.GetBytes(payload, "tools")
	if tools.IsArray() {
		tools.ForEach(func(_, tool gjson.Result) bool {
			checkCC(tool.Get("cache_control"))
			return !violates
		})
	}

	system := gjson.GetBytes(payload, "system")
	if system.IsArray() {
		system.ForEach(func(_, item gjson.Result) bool {
			checkCC(item.Get("cache_control"))
			return !violates
		})
	}

	messages := gjson.GetBytes(payload, "messages")
	if messages.IsArray() {
		messages.ForEach(func(_, msg gjson.Result) bool {
			content := msg.Get("content")
			if content.IsArray() {
				content.ForEach(func(_, item gjson.Result) bool {
					checkCC(item.Get("cache_control"))
					return !violates
				})
			}
			return !violates
		})
	}

	return violates
}

func TestClaudeExecutor_Execute_InvalidGzipErrorBodyReturnsDecodeMessage(t *testing.T) {
	testClaudeExecutorInvalidCompressedErrorBody(t, func(executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error {
		_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet-20241022",
			Payload: payload,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
		return err
	})
}

func TestClaudeExecutor_ExecuteStream_InvalidGzipErrorBodyReturnsDecodeMessage(t *testing.T) {
	testClaudeExecutorInvalidCompressedErrorBody(t, func(executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error {
		_, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet-20241022",
			Payload: payload,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
		return err
	})
}

func TestClaudeExecutor_CountTokens_InvalidGzipErrorBodyReturnsDecodeMessage(t *testing.T) {
	testClaudeExecutorInvalidCompressedErrorBody(t, func(executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error {
		_, err := executor.CountTokens(context.Background(), auth, cliproxyexecutor.Request{
			Model:   "claude-3-5-sonnet-20241022",
			Payload: payload,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
		return err
	})
}

func testClaudeExecutorInvalidCompressedErrorBody(
	t *testing.T,
	invoke func(executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error,
) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("not-a-valid-gzip-stream"))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	err := invoke(executor, auth, payload)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode error response body") {
		t.Fatalf("expected decode failure message, got: %v", err)
	}
	if statusProvider, ok := err.(interface{ StatusCode() int }); !ok || statusProvider.StatusCode() != http.StatusBadRequest {
		t.Fatalf("expected status code 400, got: %v", err)
	}
}

func TestEnsureModelMaxTokens_UsesRegisteredMaxCompletionTokens(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	clientID := "test-claude-max-completion-tokens-client"
	modelID := "test-claude-max-completion-tokens-model"
	reg.RegisterClient(clientID, "claude", []*registry.ModelInfo{{
		ID:                  modelID,
		Type:                "claude",
		OwnedBy:             "anthropic",
		Object:              "model",
		Created:             time.Now().Unix(),
		MaxCompletionTokens: 4096,
		UserDefined:         true,
	}})
	defer reg.UnregisterClient(clientID)

	input := []byte(`{"model":"test-claude-max-completion-tokens-model","messages":[{"role":"user","content":"hi"}]}`)
	out := ensureModelMaxTokens(input, modelID)

	if got := gjson.GetBytes(out, "max_tokens").Int(); got != 4096 {
		t.Fatalf("max_tokens = %d, want %d", got, 4096)
	}
}

func TestEnsureModelMaxTokens_DefaultsMissingValue(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	clientID := "test-claude-default-max-tokens-client"
	modelID := "test-claude-default-max-tokens-model"
	reg.RegisterClient(clientID, "claude", []*registry.ModelInfo{{
		ID:          modelID,
		Type:        "claude",
		OwnedBy:     "anthropic",
		Object:      "model",
		Created:     time.Now().Unix(),
		UserDefined: true,
	}})
	defer reg.UnregisterClient(clientID)

	input := []byte(`{"model":"test-claude-default-max-tokens-model","messages":[{"role":"user","content":"hi"}]}`)
	out := ensureModelMaxTokens(input, modelID)

	if got := gjson.GetBytes(out, "max_tokens").Int(); got != defaultModelMaxTokens {
		t.Fatalf("max_tokens = %d, want %d", got, defaultModelMaxTokens)
	}
}

func TestEnsureModelMaxTokens_PreservesExplicitValue(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	clientID := "test-claude-preserve-max-tokens-client"
	modelID := "test-claude-preserve-max-tokens-model"
	reg.RegisterClient(clientID, "claude", []*registry.ModelInfo{{
		ID:                  modelID,
		Type:                "claude",
		OwnedBy:             "anthropic",
		Object:              "model",
		Created:             time.Now().Unix(),
		MaxCompletionTokens: 4096,
		UserDefined:         true,
	}})
	defer reg.UnregisterClient(clientID)

	input := []byte(`{"model":"test-claude-preserve-max-tokens-model","max_tokens":2048,"messages":[{"role":"user","content":"hi"}]}`)
	out := ensureModelMaxTokens(input, modelID)

	if got := gjson.GetBytes(out, "max_tokens").Int(); got != 2048 {
		t.Fatalf("max_tokens = %d, want %d", got, 2048)
	}
}

func TestEnsureModelMaxTokens_SkipsUnregisteredModel(t *testing.T) {
	input := []byte(`{"model":"test-claude-unregistered-model","messages":[{"role":"user","content":"hi"}]}`)
	out := ensureModelMaxTokens(input, "test-claude-unregistered-model")

	if gjson.GetBytes(out, "max_tokens").Exists() {
		t.Fatalf("max_tokens should remain unset, got %s", gjson.GetBytes(out, "max_tokens").Raw)
	}
}

func TestClaudeExecutor_ExecuteStream_UsesClaudeCodeAcceptHeaders(t *testing.T) {
	var gotEncoding, gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Accept-Encoding")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"message_stop\"}\n\n"))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("unexpected chunk error: %v", chunk.Err)
		}
	}

	if gotEncoding != "gzip, deflate, br, zstd" {
		t.Errorf("Accept-Encoding = %q, want %q", gotEncoding, "gzip, deflate, br, zstd")
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want %q", gotAccept, "application/json")
	}
}

// TestClaudeExecutor_Execute_SetsCompressedAcceptEncoding verifies that non-streaming
// requests keep the full accept-encoding to allow response compression (which
// decodeResponseBody handles correctly).
func TestClaudeExecutor_Execute_SetsCompressedAcceptEncoding(t *testing.T) {
	var gotEncoding, gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Accept-Encoding")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet-20241022","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	if gotEncoding != "gzip, deflate, br, zstd" {
		t.Errorf("Accept-Encoding = %q, want %q", gotEncoding, "gzip, deflate, br, zstd")
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want %q", gotAccept, "application/json")
	}
}

// TestClaudeExecutor_ExecuteStream_GzipSuccessBodyDecoded verifies that a streaming
// HTTP 200 response with Content-Encoding: gzip is correctly decompressed before
// the line scanner runs, so SSE chunks are not silently dropped.
func TestClaudeExecutor_ExecuteStream_GzipSuccessBodyDecoded(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("data: {\"type\":\"message_stop\"}\n"))
	_ = gz.Close()
	compressedBody := buf.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressedBody)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}

	var combined strings.Builder
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("chunk error: %v", chunk.Err)
		}
		combined.Write(chunk.Payload)
	}

	if combined.Len() == 0 {
		t.Fatal("expected at least one chunk from gzip-encoded SSE body, got none (body was not decompressed)")
	}
	if !strings.Contains(combined.String(), "message_stop") {
		t.Errorf("expected SSE content in chunks, got: %q", combined.String())
	}
}

// TestDecodeResponseBody_MagicByteGzipNoHeader verifies that decodeResponseBody
// detects gzip-compressed content via magic bytes even when Content-Encoding is absent.
func TestDecodeResponseBody_MagicByteGzipNoHeader(t *testing.T) {
	const plaintext = "data: {\"type\":\"message_stop\"}\n"

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(plaintext))
	_ = gz.Close()

	rc := io.NopCloser(&buf)
	decoded, err := decodeResponseBody(rc, "")
	if err != nil {
		t.Fatalf("decodeResponseBody error: %v", err)
	}
	defer decoded.Close()

	got, err := io.ReadAll(decoded)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(got) != plaintext {
		t.Errorf("decoded = %q, want %q", got, plaintext)
	}
}

// TestDecodeResponseBody_MagicByteZstdNoHeader verifies that decodeResponseBody
// detects zstd-compressed content via magic bytes even when Content-Encoding is absent.
func TestDecodeResponseBody_MagicByteZstdNoHeader(t *testing.T) {
	const plaintext = "data: {\"type\":\"message_stop\"}\n"

	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	_, _ = enc.Write([]byte(plaintext))
	_ = enc.Close()

	rc := io.NopCloser(&buf)
	decoded, err := decodeResponseBody(rc, "")
	if err != nil {
		t.Fatalf("decodeResponseBody error: %v", err)
	}
	defer decoded.Close()

	got, err := io.ReadAll(decoded)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(got) != plaintext {
		t.Errorf("decoded = %q, want %q", got, plaintext)
	}
}

// TestDecodeResponseBody_PlainTextNoHeader verifies that decodeResponseBody returns
// plain text untouched when Content-Encoding is absent and no magic bytes match.
func TestDecodeResponseBody_PlainTextNoHeader(t *testing.T) {
	const plaintext = "data: {\"type\":\"message_stop\"}\n"
	rc := io.NopCloser(strings.NewReader(plaintext))
	decoded, err := decodeResponseBody(rc, "")
	if err != nil {
		t.Fatalf("decodeResponseBody error: %v", err)
	}
	defer decoded.Close()

	got, err := io.ReadAll(decoded)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(got) != plaintext {
		t.Errorf("decoded = %q, want %q", got, plaintext)
	}
}

// TestClaudeExecutor_ExecuteStream_GzipNoContentEncodingHeader verifies the full
// pipeline: when the upstream returns a gzip-compressed SSE body WITHOUT setting
// Content-Encoding (a misbehaving upstream), the magic-byte sniff in
// decodeResponseBody still decompresses it, so chunks reach the caller.
func TestClaudeExecutor_ExecuteStream_GzipNoContentEncodingHeader(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("data: {\"type\":\"message_stop\"}\n"))
	_ = gz.Close()
	compressedBody := buf.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Intentionally omit Content-Encoding to simulate misbehaving upstream.
		_, _ = w.Write(compressedBody)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}

	var combined strings.Builder
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("chunk error: %v", chunk.Err)
		}
		combined.Write(chunk.Payload)
	}

	if combined.Len() == 0 {
		t.Fatal("expected chunks from gzip body without Content-Encoding header, got none (magic-byte sniff failed)")
	}
	if !strings.Contains(combined.String(), "message_stop") {
		t.Errorf("unexpected chunk content: %q", combined.String())
	}
}

// TestClaudeExecutor_Execute_GzipErrorBodyNoContentEncodingHeader verifies that the
// error path (4xx) correctly decompresses a gzip body even when the upstream omits
// the Content-Encoding header.  This closes the gap left by PR #1771, which only
// fixed header-declared compression on the error path.
func TestClaudeExecutor_Execute_GzipErrorBodyNoContentEncodingHeader(t *testing.T) {
	const errJSON = `{"type":"error","error":{"type":"invalid_request_error","message":"test error"}}`

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(errJSON))
	_ = gz.Close()
	compressedBody := buf.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Intentionally omit Content-Encoding to simulate misbehaving upstream.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(compressedBody)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err == nil {
		t.Fatal("expected an error for 400 response, got nil")
	}
	if !strings.Contains(err.Error(), "test error") {
		t.Errorf("error message should contain decompressed JSON, got: %q", err.Error())
	}
}

// TestClaudeExecutor_ExecuteStream_GzipErrorBodyNoContentEncodingHeader verifies
// the same for the streaming executor: 4xx gzip body without Content-Encoding is
// decoded and the error message is readable.
func TestClaudeExecutor_ExecuteStream_GzipErrorBodyNoContentEncodingHeader(t *testing.T) {
	const errJSON = `{"type":"error","error":{"type":"invalid_request_error","message":"stream test error"}}`

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(errJSON))
	_ = gz.Close()
	compressedBody := buf.Bytes()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Intentionally omit Content-Encoding to simulate misbehaving upstream.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(compressedBody)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err == nil {
		t.Fatal("expected an error for 400 response, got nil")
	}
	if !strings.Contains(err.Error(), "stream test error") {
		t.Errorf("error message should contain decompressed JSON, got: %q", err.Error())
	}
}

func TestClaudeExecutor_ExecuteStream_AcceptEncodingOverrideStillApplies(t *testing.T) {
	var gotEncoding string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"message_stop\"}\n\n"))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":                "key-123",
		"base_url":               server.URL,
		"header:Accept-Encoding": "identity",
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("unexpected chunk error: %v", chunk.Err)
		}
	}

	if gotEncoding != "identity" {
		t.Errorf("Accept-Encoding = %q, want explicit custom override identity", gotEncoding)
	}
}

func expectedForwardedSystemReminder(text string) string {
	return fmt.Sprintf(`<system-reminder>
As you answer the user's questions, you can use the following context from the system:
%s

IMPORTANT: this context may or may not be relevant to your tasks. You should not respond to this context unless it is highly relevant to your task.
</system-reminder>
`, text)
}

// Test case 1: String system prompt is preserved by forwarding it to the first user message
func TestCheckSystemInstructionsWithMode_StringSystemPreserved(t *testing.T) {
	payload := []byte(`{"system":"You are a helpful assistant.","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)

	system := gjson.GetBytes(out, "system")
	if !system.IsArray() {
		t.Fatalf("system should be an array, got %s", system.Type)
	}

	blocks := system.Array()
	if len(blocks) != 4 {
		t.Fatalf("expected 4 system blocks, got %d", len(blocks))
	}

	if !strings.HasPrefix(blocks[0].Get("text").String(), "x-anthropic-billing-header:") {
		t.Fatalf("blocks[0] should be billing header, got %q", blocks[0].Get("text").String())
	}
	if blocks[1].Get("text").String() != "You are Claude Code, Anthropic's official CLI for Claude." {
		t.Fatalf("blocks[1] should be agent block, got %q", blocks[1].Get("text").String())
	}
	if !strings.Contains(blocks[2].Get("text").String(), "# Doing tasks") {
		t.Fatalf("blocks[2] should be full static prompt, got %q", blocks[2].Get("text").String())
	}
	if !strings.HasPrefix(blocks[3].Get("text").String(), "# Text output") {
		t.Fatalf("blocks[3] should be the dynamic prompt block, got %q", blocks[3].Get("text").String())
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.text").String(); got != expectedForwardedSystemReminder("You are a helpful assistant.") {
		t.Fatalf("messages[0].content[0] should contain the forwarded system prompt, got %q", got)
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.text").String(); got != "hi" {
		t.Fatalf("messages[0].content[1] = %q, want hi", got)
	}
}

// Test case 2: Strict mode keeps only the injected Claude Code system blocks
func TestCheckSystemInstructionsWithMode_StringSystemStrict(t *testing.T) {
	payload := []byte(`{"system":"You are a helpful assistant.","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, true)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 4 {
		t.Fatalf("strict mode should produce 4 injected blocks, got %d", len(blocks))
	}
	if got := gjson.GetBytes(out, "messages.0.content").String(); got != "hi" {
		t.Fatalf("strict mode should not forward system prompt into messages, got %q", got)
	}
}

// Test case 3: Empty string system prompt does not alter the first user message
func TestCheckSystemInstructionsWithMode_EmptyStringSystemIgnored(t *testing.T) {
	payload := []byte(`{"system":"","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 4 {
		t.Fatalf("empty string system should still produce 4 injected blocks, got %d", len(blocks))
	}
	if got := gjson.GetBytes(out, "messages.0.content").String(); got != "hi" {
		t.Fatalf("empty string system should not alter messages, got %q", got)
	}
}

// Test case 4: Array system prompt is forwarded to the first user message
func TestCheckSystemInstructionsWithMode_ArraySystemStillWorks(t *testing.T) {
	payload := []byte(`{"system":[{"type":"text","text":"Be concise."}],"messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 4 {
		t.Fatalf("expected 4 system blocks, got %d", len(blocks))
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.text").String(); got != expectedForwardedSystemReminder("Be concise.") {
		t.Fatalf("messages[0].content[0] should contain the forwarded system prompt, got %q", got)
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.text").String(); got != "hi" {
		t.Fatalf("messages[0].content[1] = %q, want hi", got)
	}
}

// Test case 5: Special characters in string system prompt survive forwarding
func TestCheckSystemInstructionsWithMode_StringWithSpecialChars(t *testing.T) {
	payload := []byte(`{"system":"Use <xml> tags & \"quotes\" in output.","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 4 {
		t.Fatalf("expected 4 system blocks, got %d", len(blocks))
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.text").String(); got != expectedForwardedSystemReminder(`Use <xml> tags & "quotes" in output.`) {
		t.Fatalf("forwarded system prompt text mangled, got %q", got)
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.text").String(); got != "hi" {
		t.Fatalf("messages[0].content[1] = %q, want hi", got)
	}
}

func TestCheckSystemInstructionsWithSigningMode_OAuthPreservesClientContent(t *testing.T) {
	payload := []byte(`{"system":[{"type":"text","text":"Keep this exact client rule."}],"tools":[{"name":"client_tool","description":"Client tool","input_schema":{"type":"object"}}],"tool_choice":{"type":"tool","name":"client_tool"},"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	out := checkSystemInstructionsWithSigningMode(payload, false, false, true, "2.1.215", "cli", "")

	if got := len(gjson.GetBytes(out, "system").Array()); got != 4 {
		t.Fatalf("expected the four official Claude Code system blocks, got %d", got)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.text").String(); got != expectedForwardedSystemReminder("Keep this exact client rule.") {
		t.Fatalf("client system content was not preserved, got %q", got)
	}
	if got := gjson.GetBytes(out, "tools").Raw; got != gjson.GetBytes(payload, "tools").Raw {
		t.Fatalf("client tools changed: got %s", got)
	}
	if got := gjson.GetBytes(out, "tool_choice").Raw; got != gjson.GetBytes(payload, "tool_choice").Raw {
		t.Fatalf("client tool_choice changed: got %s", got)
	}
}

func TestClaudeExecutor_OAuthCustomBaseFullCloakPreservesClientContent(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{"base_url": server.URL},
		Metadata:   map[string]any{"access_token": "sk-ant-oat-test"},
	}
	payload := []byte(`{"system":[{"type":"text","text":"  Keep this exact client rule.  "}],"tools":[{"name":"client_tool","description":"Client tool","input_schema":{"type":"object","properties":{"value":{"type":"string"}}}}],"tool_choice":{"type":"tool","name":"client_tool"},"messages":[{"role":"user","content":[{"type":"text","text":"original user text"}]}]}`)

	_, errExecute := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	blocks := gjson.GetBytes(seenBody, "system").Array()
	if len(blocks) != 4 {
		t.Fatalf("expected the four official Claude Code system blocks, got %d: %s", len(blocks), gjson.GetBytes(seenBody, "system").Raw)
	}
	if got := blocks[1].Get("text").String(); got != "You are a Claude agent, built on Anthropic's Claude Agent SDK." {
		t.Fatalf("identity block = %q", got)
	}
	if !strings.Contains(blocks[2].Get("text").String(), "# Doing tasks") {
		t.Fatalf("full static prompt missing Doing tasks section: %q", blocks[2].Get("text").String())
	}
	if !strings.HasPrefix(blocks[3].Get("text").String(), "# Text output") {
		t.Fatalf("dynamic prompt missing Text output section: %q", blocks[3].Get("text").String())
	}
	if got := gjson.GetBytes(seenBody, "messages.0.content.0.text").String(); got != expectedForwardedSystemReminder("  Keep this exact client rule.  ") {
		t.Fatalf("client system content was not preserved, got %q", got)
	}
	if got := gjson.GetBytes(seenBody, "messages.0.content.1.text").String(); got != "original user text" {
		t.Fatalf("original user content changed, got %q", got)
	}
	if got := gjson.GetBytes(seenBody, "tools.0.name").String(); got != "client_tool" {
		t.Fatalf("client tool name changed, got %q", got)
	}
	if got := gjson.GetBytes(seenBody, "tools.0.description").String(); got != "Client tool" {
		t.Fatalf("client tool description changed, got %q", got)
	}
	if got := gjson.GetBytes(seenBody, "tools.0.input_schema.properties.value.type").String(); got != "string" {
		t.Fatalf("client tool schema changed, got %q", got)
	}
	if got := gjson.GetBytes(seenBody, "tool_choice.name").String(); got != "client_tool" {
		t.Fatalf("client tool_choice changed, got %q", got)
	}

	if strings.Contains(blocks[0].Get("text").String(), " cch=") {
		t.Fatalf("custom base URL should not receive first-party cch: %s", seenBody)
	}
}

func TestCheckSystemInstructionsWithSigningMode_UsesClaude215UserFingerprint(t *testing.T) {
	payload := []byte(`{"system":[{"type":"text","text":"Different system text"}],"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)

	out := checkSystemInstructionsWithSigningMode(payload, true, false, false, "2.1.215", "sdk-cli", "")

	if got, want := gjson.GetBytes(out, "system.0.text").String(), "x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=sdk-cli;"; got != want {
		t.Fatalf("billing header = %q, want %q", got, want)
	}
}

func TestCheckSystemInstructionsWithSigningMode_UserFingerprintSkipsInjectedReminders(t *testing.T) {
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"<system-reminder>\nAvailable agent types for the Agent tool.\n</system-reminder>"},{"type":"text","text":"<system-reminder>\nCurrent date context.\n</system-reminder>"},{"type":"text","text":"Reply only OK"}]}]}`)

	out := checkSystemInstructionsWithSigningMode(payload, true, false, false, "2.1.215", "sdk-cli", "")

	if got, want := gjson.GetBytes(out, "system.0.text").String(), "x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=sdk-cli;"; got != want {
		t.Fatalf("billing header = %q, want %q", got, want)
	}
}

func TestCheckSystemInstructionsWithSigningMode_SDKCLIIdentityMatchesClaude215(t *testing.T) {
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)

	out := checkSystemInstructionsWithSigningMode(payload, true, false, false, "2.1.215", "sdk-cli", "")

	if got, want := gjson.GetBytes(out, "system.1.text").String(), "You are a Claude agent, built on Anthropic's Claude Agent SDK."; got != want {
		t.Fatalf("sdk-cli identity = %q, want %q", got, want)
	}
	if gjson.GetBytes(out, "system.1.cache_control").Exists() {
		t.Fatalf("sdk-cli identity should not include cache_control: %s", gjson.GetBytes(out, "system.1").Raw)
	}

	cliOut := checkSystemInstructionsWithSigningMode(payload, true, false, false, "2.1.215", "cli", "")
	if got, want := gjson.GetBytes(cliOut, "system.1.text").String(), "You are Claude Code, Anthropic's official CLI for Claude."; got != want {
		t.Fatalf("cli identity = %q, want %q", got, want)
	}
	if gjson.GetBytes(cliOut, "system.1.cache_control").Exists() {
		t.Fatalf("cli identity should not include cache_control: %s", gjson.GetBytes(cliOut, "system.1").Raw)
	}
}

func TestCheckSystemInstructionsWithFullSystemPrompt_AddsStaticPromptBlock(t *testing.T) {
	payload := []byte(`{"system":[{"type":"text","text":"Client rule"}],"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, false, "2.1.215", "sdk-cli", "", true)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 4 {
		t.Fatalf("system block count = %d, want 4: %s", len(blocks), gjson.GetBytes(out, "system").Raw)
	}
	if got, want := blocks[0].Get("text").String(), "x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=sdk-cli;"; got != want {
		t.Fatalf("billing header = %q, want %q", got, want)
	}
	if got, want := blocks[1].Get("text").String(), "You are a Claude agent, built on Anthropic's Claude Agent SDK."; got != want {
		t.Fatalf("identity block = %q, want %q", got, want)
	}
	if blocks[1].Get("cache_control").Exists() {
		t.Fatalf("identity must not include cache_control: %s", blocks[1].Raw)
	}
	staticPrompt := blocks[2].Get("text").String()
	for _, want := range []string{
		"You are an interactive agent that helps users with software engineering tasks.",
		"# System",
		"# Doing tasks",
		"# Executing actions with care",
		"# Using your tools",
		"# Tone and style",
	} {
		if !strings.Contains(staticPrompt, want) {
			t.Fatalf("static prompt missing %q: %q", want, staticPrompt)
		}
	}
	if got := blocks[2].Get("cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("static prompt cache_control.type = %q, want ephemeral", got)
	}
	if strings.Contains(staticPrompt, "# Text output") {
		t.Fatalf("system[2] must end before Text output: %q", staticPrompt)
	}
	if got := blocks[3].Get("text").String(); got != helps.ClaudeCodeTextOutput {
		t.Fatalf("system[3] dynamic prompt = %q", got)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.text").String(); got != expectedForwardedSystemReminder("Client rule") {
		t.Fatalf("client system content was not preserved, got %q", got)
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.text").String(); got != "Reply only OK" {
		t.Fatalf("original user text changed, got %q", got)
	}
}

func TestClaudeCodeStaticSystemPromptFollowsEffectiveCustomerTools(t *testing.T) {
	tests := []struct {
		name                      string
		tools                     string
		hasBash, hasTask, hasTodo bool
	}{
		{name: "empty", tools: `[]`},
		{name: "Bash only", tools: `[{"name":"Bash"}]`, hasBash: true},
		{name: "TaskCreate only", tools: `[{"name":"TaskCreate"}]`, hasTask: true},
		{name: "default deferred registry", tools: `[{"name":"Bash"},{"name":"DeferredToolPlaceholder"}]`, hasBash: true, hasTask: true},
		{name: "Bash TaskCreate", tools: `[{"name":"Bash"},{"name":"TaskCreate"}]`, hasBash: true, hasTask: true},
		{name: "legacy TodoWrite", tools: `[{"name":"TodoWrite"}]`, hasTodo: true},
		{name: "TaskCreate wins over TodoWrite", tools: `[{"name":"TodoWrite"},{"name":"TaskCreate"}]`, hasTask: true, hasTodo: true},
		{name: "whitespace is not an official tool name", tools: `[{"name":" Bash "}]`},
		{name: "unknown", tools: `[{"name":"customer_tool"}]`},
		{name: "CPA lowercase aliases normalize before upstream", tools: `[{"name":"bash"},{"name":"taskcreate"}]`, hasBash: true, hasTask: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte(`{"tools":` + test.tools + `}`)
			got := claudeCodeStaticSystemPromptForPayload(payload)
			want := helps.ClaudeCodeStaticSystemPromptForTools(test.hasBash, test.hasTask, test.hasTodo)
			if got != want {
				t.Fatalf("tool-conditioned static prompt differs")
			}
		})
	}
}

func TestClaudeCodeStaticSystemPromptFollowsNativeModelBranches(t *testing.T) {
	for _, test := range []struct {
		model string
		want  string
	}{
		{model: "claude-opus-4-8", want: helps.ClaudeCodeLeanStaticSystemPrompt},
		{model: "claude-fable-5", want: helps.ClaudeCodeFableLeanStaticSystemPrompt},
		{model: "claude-mythos-5", want: helps.ClaudeCodeFableLeanStaticSystemPrompt},
		{model: "fixture-unknown-model", want: helps.ClaudeCodeLeanStaticSystemPrompt},
		{model: "claude-sonnet-5", want: helps.ClaudeCodeStaticSystemPrompt},
		{model: "claude-haiku-4-5-20251001", want: helps.ClaudeCodeStaticSystemPrompt},
	} {
		t.Run(test.model, func(t *testing.T) {
			payload := []byte(`{"model":"` + test.model + `","tools":[{"name":"Bash"},{"name":"DeferredToolPlaceholder"}]}`)
			if got := claudeCodeStaticSystemPromptForPayload(payload); got != test.want {
				t.Fatalf("model-conditioned static prompt differs")
			}
		})
	}
}

func TestClaudeCodePromptEnvironmentOverrides(t *testing.T) {
	tests := []struct {
		name        string
		model       string
		simple      string
		investigate string
		wantStatic  string
		wantDynamic string
	}{
		{
			name:        "Sonnet forced lean",
			model:       "claude-sonnet-4-6",
			simple:      "true",
			wantStatic:  helps.ClaudeCodeLeanStaticSystemPrompt,
			wantDynamic: helps.ClaudeCodeOpus48DynamicPromptPrefix,
		},
		{
			name:        "Opus 4.8 forced normal",
			model:       "claude-opus-4-8",
			simple:      "false",
			wantStatic:  helps.ClaudeCodeStaticSystemPrompt,
			wantDynamic: helps.ClaudeCodeTextOutput,
		},
		{
			name:        "Opus 4.7 compact investigate",
			model:       "claude-opus-4-7",
			investigate: "compact",
			wantStatic:  helps.ClaudeCodeCompactStaticSystemPromptForTools(true, true, false),
			wantDynamic: helps.ClaudeCodeInvestigateFirstDynamicPromptPrefix,
		},
		{
			name:        "Fable forced normal mid-conv",
			model:       "claude-fable-5",
			simple:      "false",
			wantStatic:  helps.ClaudeCodeMidConvStaticSystemPromptForTools(true, true, false),
			wantDynamic: helps.ClaudeCodeFableNormalDynamicPromptPrefix,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("CLAUDE_CODE_SIMPLE_SYSTEM_PROMPT", test.simple)
			t.Setenv("CLAUDE_CODE_INVESTIGATE_FIRST", test.investigate)
			payload := []byte(`{"model":"` + test.model + `","tools":[{"name":"Bash"},{"name":"DeferredToolPlaceholder"}],"messages":[{"role":"user","content":"hello"}]}`)
			out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, true, "2.1.216", "sdk-cli", "", true)
			if got := gjson.GetBytes(out, "system.2.text").String(); got != test.wantStatic {
				t.Fatalf("system[2] differs from selected native branch")
			}
			if got := gjson.GetBytes(out, "system.3.text").String(); got != test.wantDynamic {
				t.Fatalf("system[3] differs from selected native branch")
			}
		})
	}
}

func TestClaudeCodeClientCompactPromptIsPreservedAndIdempotent(t *testing.T) {
	t.Setenv("CLAUDE_CODE_SIMPLE_SYSTEM_PROMPT", "")
	t.Setenv("CLAUDE_CODE_INVESTIGATE_FIRST", "off")
	clientDynamic := helps.ClaudeCodeInvestigateFirstDynamicPromptPrefix + "\n\n# Environment\n- Primary working directory: /client/project"
	payload := []byte(`{"model":"claude-opus-4-7","tools":[{"name":"Bash"},{"name":"DeferredToolPlaceholder"}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.216.a1b; cc_entrypoint=sdk-cli; cch=931de;"},{"type":"text","text":"You are a Claude agent, built on Anthropic's Claude Agent SDK."},{"type":"text","text":""},{"type":"text","text":""}],"messages":[{"role":"user","content":"hello"}]}`)
	payload, _ = sjson.SetBytes(payload, "system.2.text", helps.ClaudeCodeCompactStaticSystemPromptForTools(true, true, false))
	payload, _ = sjson.SetBytes(payload, "system.3.text", clientDynamic)

	first := checkSystemInstructionsWithFullSystemPrompt(payload, false, true, true, "2.1.216", "sdk-cli", "", true)
	if got := gjson.GetBytes(first, "system.2.text").String(); got != helps.ClaudeCodeCompactStaticSystemPromptForTools(true, true, false) {
		t.Fatal("client compact system[2] branch was not preserved")
	}
	if got := gjson.GetBytes(first, "system.3.text").String(); got != clientDynamic {
		t.Fatalf("client compact system[3] or dynamic suffix changed\nGOT:\n%s\nWANT:\n%s", got, clientDynamic)
	}
	if got := gjson.GetBytes(first, "messages.0.content").String(); got != "hello" {
		t.Fatalf("official client prompt leaked into user message: %q", got)
	}

	second := checkSystemInstructionsWithFullSystemPrompt(first, false, true, true, "2.1.216", "sdk-cli", "", true)
	if got, want := gjson.GetBytes(second, "system").Raw, gjson.GetBytes(first, "system").Raw; got != want {
		t.Fatalf("second compact cloak pass changed system blocks\nfirst:  %s\nsecond: %s", want, got)
	}
}

func TestClaudeCodeOfficialDynamicBlockPreservesEveryClientSection(t *testing.T) {
	clientSuffix := "Optional unheaded native guidance.\n\n# Memory\nCLIENT_MEMORY\n\n# Language\nAlways respond in Chinese.\n\n# Output Style: Detailed\n# Nested customer heading\nKeep this heading inside the client block.\n\n# Focus mode\nCLIENT_FOCUS"
	clientDynamic := helps.ClaudeCodeTextOutput + "\n\n" + clientSuffix
	payload := []byte(`{"model":"claude-sonnet-4-6","tools":[{"name":"Bash"},{"name":"DeferredToolPlaceholder"}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.216.a1b; cc_entrypoint=sdk-cli; cch=931de;"},{"type":"text","text":"You are a Claude agent, built on Anthropic's Claude Agent SDK."},{"type":"text","text":""},{"type":"text","text":""}],"messages":[{"role":"user","content":"hello"}]}`)
	payload, _ = sjson.SetBytes(payload, "system.2.text", helps.ClaudeCodeStaticSystemPrompt)
	payload, _ = sjson.SetBytes(payload, "system.3.text", clientDynamic)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, true, "2.1.216", "sdk-cli", "", true)
	if got := gjson.GetBytes(out, "system.3.text").String(); got != clientDynamic {
		t.Fatalf("official client system[3] changed\nGOT:\n%s\nWANT:\n%s", got, clientDynamic)
	}
	if got := gjson.GetBytes(out, "messages.0.content").String(); got != "hello" {
		t.Fatalf("official system[3] content leaked into user message: %q", got)
	}
}

func TestClaudeCodeDynamicPromotionIgnoresCustomerFences(t *testing.T) {
	clientSystem := helps.ClaudeCodeStaticSystemPrompt + "\n\n```text\n# Environment\nCUSTOM_LITERAL\n```\n\n# Environment\nREAL_DYNAMIC"
	payload := []byte(`{"model":"claude-sonnet-4-6","system":[{"type":"text","text":""}],"messages":[{"role":"user","content":"hello"}]}`)
	payload, _ = sjson.SetBytes(payload, "system.0.text", clientSystem)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, true, "2.1.216", "sdk-cli", "", true)
	dynamic := gjson.GetBytes(out, "system.3.text").String()
	if !strings.Contains(dynamic, "# Environment\nREAL_DYNAMIC") || strings.Contains(dynamic, "CUSTOM_LITERAL") {
		t.Fatalf("fenced customer literal was confused with official dynamic context: %q", dynamic)
	}
	forwarded := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !strings.Contains(forwarded, "```text\n# Environment\nCUSTOM_LITERAL\n```") {
		t.Fatalf("fenced customer literal was not preserved: %q", forwarded)
	}
}

func TestClaudeCodeDynamicPromotionPreservesClientLineEndings(t *testing.T) {
	clientDynamic := "# Environment\r\n- Primary working directory: C:\\client\r\n- Platform: win32"
	payload := []byte(`{"model":"claude-sonnet-4-6","system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.216.a1b; cc_entrypoint=sdk-cli; cch=931de;"},{"type":"text","text":"You are a Claude agent, built on Anthropic's Claude Agent SDK."},{"type":"text","text":""},{"type":"text","text":""}],"messages":[{"role":"user","content":"hello"}]}`)
	payload, _ = sjson.SetBytes(payload, "system.2.text", helps.ClaudeCodeStaticSystemPrompt)
	payload, _ = sjson.SetBytes(payload, "system.3.text", clientDynamic)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, true, "2.1.216", "sdk-cli", "", true)
	want := helps.ClaudeCodeTextOutput + "\n\n" + clientDynamic
	if got := gjson.GetBytes(out, "system.3.text").String(); got != want {
		t.Fatalf("client dynamic line endings changed\nGOT:  %q\nWANT: %q", got, want)
	}
}

func TestProtectedClaudeCodeCacheControlsRecognizeEveryDynamicPrefix(t *testing.T) {
	for _, test := range []struct {
		name   string
		static string
		prefix string
	}{
		{name: "normal", static: helps.ClaudeCodeStaticSystemPrompt, prefix: helps.ClaudeCodeTextOutput},
		{name: "lean", static: helps.ClaudeCodeLeanStaticSystemPrompt, prefix: helps.ClaudeCodeOpus48DynamicPromptPrefix},
		{name: "fable", static: helps.ClaudeCodeFableLeanStaticSystemPrompt, prefix: helps.ClaudeCodeFableDynamicPromptPrefix},
		{name: "mythos", static: helps.ClaudeCodeFableLeanStaticSystemPrompt, prefix: helps.ClaudeCodeMythosDynamicPromptPrefix},
		{name: "compact", static: helps.ClaudeCodeCompactStaticSystemPromptForTools(true, true, false), prefix: helps.ClaudeCodeInvestigateFirstDynamicPromptPrefix},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte(`{"system":[{},{},{"type":"text","text":"","cache_control":{"type":"ephemeral"}},{"type":"text","text":"","cache_control":{"type":"ephemeral"}}]}`)
			payload, _ = sjson.SetBytes(payload, "system.2.text", test.static)
			payload, _ = sjson.SetBytes(payload, "system.3.text", test.prefix+"\n\n# Environment\nCLIENT")
			protected, official := protectedClaudeCodeCacheControlPaths(payload)
			if !official {
				t.Fatal("official prompt pair was not recognized")
			}
			for _, path := range []string{"system.2.cache_control", "system.3.cache_control"} {
				if _, ok := protected[path]; !ok {
					t.Fatalf("%s was not protected: %#v", path, protected)
				}
			}
		})
	}
}

func TestCheckSystemInstructionsWithFullSystemPrompt_DedupesFullClientStaticPrompt(t *testing.T) {
	payload := []byte(`{"system":[{"type":"text","text":""}],"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)
	payload, _ = sjson.SetBytes(payload, "system.0.text", helps.ClaudeCodeStaticSystemPrompt)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, false, "2.1.215", "sdk-cli", "", true)

	if got := len(gjson.GetBytes(out, "system").Array()); got != 4 {
		t.Fatalf("system block count = %d, want 4: %s", got, gjson.GetBytes(out, "system").Raw)
	}
	if got := gjson.GetBytes(out, "messages.0.content.#").Int(); got != 1 {
		t.Fatalf("messages.0.content count = %d, want 1: %s", got, gjson.GetBytes(out, "messages.0.content").Raw)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.text").String(); got != "Reply only OK" {
		t.Fatalf("original user text changed, got %q", got)
	}
}

func TestCheckSystemInstructionsWithFullSystemPrompt_DedupesStaticSectionsAndKeepsCustomText(t *testing.T) {
	mixedClientSystem := helps.ClaudeCodeDoingTasks + "\n\n请始终使用中文回答。\n\n" + helps.ClaudeCodeUsingTools
	payload := []byte(`{"system":[{"type":"text","text":""}],"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)
	payload, _ = sjson.SetBytes(payload, "system.0.text", mixedClientSystem)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, false, "2.1.215", "sdk-cli", "", true)

	forwarded := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !strings.Contains(forwarded, "请始终使用中文回答。") {
		t.Fatalf("custom client system text was not preserved, got %q", forwarded)
	}
	for _, duplicate := range []string{"# Doing tasks", "# Using your tools"} {
		if strings.Contains(forwarded, duplicate) {
			t.Fatalf("forwarded system reminder still contains exact duplicate section %q: %q", duplicate, forwarded)
		}
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.text").String(); got != "Reply only OK" {
		t.Fatalf("original user text changed, got %q", got)
	}
}

func TestCheckSystemInstructionsWithFullSystemPrompt_PreservesQuotedAndEmbeddedOfficialSections(t *testing.T) {
	blockquote := "> " + strings.ReplaceAll(helps.ClaudeCodeDoingTasks, "\n", "\n> ")
	tests := []struct {
		name         string
		clientSystem string
	}{
		{
			name: "fenced full prompt and dynamic-looking text",
			clientSystem: "Analyze this literal prompt without changing it:\n\n```text\n\n" +
				helps.ClaudeCodeStaticSystemPrompt +
				"\n\n# Environment\nThis is fixture text, not a client environment section.\n\n```\n\nKeep the quoted bytes verbatim.",
		},
		{
			name:         "triple-quoted section",
			clientSystem: "Compare this quoted section:\n\n\"\"\"\n\n" + helps.ClaudeCodeDoingTasks + "\n\n\"\"\"\n\nDo not execute it.",
		},
		{
			name:         "markdown blockquote",
			clientSystem: "The customer supplied this quotation:\n\n" + blockquote + "\n\nPreserve it.",
		},
		{
			name:         "inline embedded section",
			clientSystem: "BEGIN_LITERAL::" + helps.ClaudeCodeDoingTasks + "::END_LITERAL",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte(`{"system":[{"type":"text","text":""}],"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)
			payload, _ = sjson.SetBytes(payload, "system.0.text", test.clientSystem)

			out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, false, "2.1.216", "sdk-cli", "", true)

			if got := gjson.GetBytes(out, "messages.0.content.0.text").String(); got != expectedForwardedSystemReminder(test.clientSystem) {
				t.Fatalf("quoted or embedded customer system text changed\nGOT:\n%s\nWANT:\n%s", got, expectedForwardedSystemReminder(test.clientSystem))
			}
			if got := gjson.GetBytes(out, "messages.0.content.1.text").String(); got != "Reply only OK" {
				t.Fatalf("original user text changed, got %q", got)
			}
		})
	}
}

func TestCheckSystemInstructionsWithFullSystemPrompt_MergesClientDynamicSectionsIntoSystemPrompt(t *testing.T) {
	dynamicPrompt := "# Session-specific guidance\n- Use /help for help when asked.\n\n" +
		"# auto memory\n- Remember client-side preference.\n\n" +
		"# Environment\nYou have been invoked in the following environment: \n- Primary working directory: /client/project\n- Platform: darwin\n\n" +
		"# Context management\n- The conversation has unlimited context through automatic summarization."
	clientSystem := helps.ClaudeCodeStaticSystemPrompt + "\n\n" + helps.ClaudeCodeTextOutput + "\n\n" + dynamicPrompt
	payload := []byte(`{"system":[{"type":"text","text":""}],"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)
	payload, _ = sjson.SetBytes(payload, "system.0.text", clientSystem)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, false, "2.1.215", "sdk-cli", "", true)

	if got := gjson.GetBytes(out, "system.2.text").String(); got != helps.ClaudeCodeStaticSystemPromptForTools(false, false, false) {
		t.Fatalf("system.2.text did not preserve the official static prompt:\nGOT:\n%s", got)
	}
	if got, want := gjson.GetBytes(out, "system.3.text").String(), helps.ClaudeCodeTextOutput+"\n\n"+dynamicPrompt; got != want {
		t.Fatalf("system.3.text did not preserve the official dynamic prompt:\nGOT:\n%s\nWANT:\n%s", got, want)
	}
	if got := gjson.GetBytes(out, "messages.0.content.#").Int(); got != 1 {
		t.Fatalf("dynamic official prompt should not be forwarded as reminder, content count = %d: %s", got, gjson.GetBytes(out, "messages.0.content").Raw)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.text").String(); got != "Reply only OK" {
		t.Fatalf("original user text changed, got %q", got)
	}
}

func TestCheckSystemInstructionsWithFullSystemPrompt_KeepsStandaloneDynamicLookingSectionsAsCustomerContext(t *testing.T) {
	clientDynamic := "# Environment\nYou have been invoked in the following environment: \n- Primary working directory: /client/project"
	payload := []byte(`{"system":[{"type":"text","text":"请始终使用中文回答。"},{"type":"text","text":""}],"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)
	payload, _ = sjson.SetBytes(payload, "system.1.text", clientDynamic)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, false, "2.1.215", "sdk-cli", "", true)

	systemPrompt := gjson.GetBytes(out, "system.3.text").String()
	if strings.Contains(systemPrompt, clientDynamic) {
		t.Fatalf("untrusted standalone section was promoted into system.3: %q", systemPrompt)
	}
	forwarded := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !strings.Contains(forwarded, "请始终使用中文回答。") || !strings.Contains(forwarded, clientDynamic) {
		t.Fatalf("custom client system text was not forwarded, got %q", forwarded)
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.text").String(); got != "Reply only OK" {
		t.Fatalf("original user text changed, got %q", got)
	}
}

func TestCheckSystemInstructionsWithFullSystemPrompt_PreservesClientDynamicSectionOrder(t *testing.T) {
	environment := "# Environment\nYou have been invoked in the following environment: \n- Primary working directory: /client/project"
	sessionGuidance := "# Session-specific guidance\n- Client session rule."
	payload := []byte(`{"system":[{"type":"text","text":""},{"type":"text","text":""}],"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)
	payload, _ = sjson.SetBytes(payload, "system.0.text", helps.ClaudeCodeStaticSystemPrompt)
	payload, _ = sjson.SetBytes(payload, "system.1.text", environment+"\n\n"+sessionGuidance)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, false, "2.1.215", "sdk-cli", "", true)

	systemPrompt := gjson.GetBytes(out, "system.3.text").String()
	sessionIdx := strings.Index(systemPrompt, "# Session-specific guidance")
	environmentIdx := strings.Index(systemPrompt, "# Environment")
	if sessionIdx < 0 || environmentIdx < 0 {
		t.Fatalf("system.3 missing dynamic sections: %q", systemPrompt)
	}
	if environmentIdx > sessionIdx {
		t.Fatalf("dynamic sections should preserve client order: environment=%d session=%d", environmentIdx, sessionIdx)
	}
	if got := gjson.GetBytes(out, "messages.0.content.#").Int(); got != 1 {
		t.Fatalf("official dynamic sections should not be forwarded, content count = %d: %s", got, gjson.GetBytes(out, "messages.0.content").Raw)
	}
}

func TestCheckSystemInstructionsWithFullSystemPrompt_KeepsSimilarButModifiedClientPrompt(t *testing.T) {
	modifiedDoingTasks := strings.Replace(helps.ClaudeCodeDoingTasks, "The user will primarily request", "The customer will primarily request", 1)
	payload := []byte(`{"system":[{"type":"text","text":""}],"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)
	payload, _ = sjson.SetBytes(payload, "system.0.text", modifiedDoingTasks)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, false, "2.1.215", "sdk-cli", "", true)

	forwarded := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !strings.Contains(forwarded, "# Doing tasks") || !strings.Contains(forwarded, "The customer will primarily request") {
		t.Fatalf("modified client prompt should be preserved, got %q", forwarded)
	}
}

func TestCheckSystemInstructionsWithFullSystemPrompt_DedupeDisabledForMinimalCloak(t *testing.T) {
	payload := []byte(`{"system":[{"type":"text","text":""}],"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)
	payload, _ = sjson.SetBytes(payload, "system.0.text", helps.ClaudeCodeDoingTasks)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, false, "2.1.215", "sdk-cli", "", false)

	if got := len(gjson.GetBytes(out, "system").Array()); got != 2 {
		t.Fatalf("system block count = %d, want 2: %s", got, gjson.GetBytes(out, "system").Raw)
	}
	forwarded := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !strings.Contains(forwarded, "# Doing tasks") {
		t.Fatalf("minimal cloak should keep client prompt unchanged, got %q", forwarded)
	}
}

func TestCheckSystemInstructionsWithFullSystemPrompt_DynamicMergeDisabledForMinimalCloak(t *testing.T) {
	clientDynamic := "# Environment\nYou have been invoked in the following environment: \n- Primary working directory: /client/project"
	payload := []byte(`{"system":[{"type":"text","text":""}],"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)
	payload, _ = sjson.SetBytes(payload, "system.0.text", clientDynamic)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, false, "2.1.215", "sdk-cli", "", false)

	if got := len(gjson.GetBytes(out, "system").Array()); got != 2 {
		t.Fatalf("system block count = %d, want 2: %s", got, gjson.GetBytes(out, "system").Raw)
	}
	forwarded := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !strings.Contains(forwarded, "# Environment") {
		t.Fatalf("minimal cloak should keep client dynamic prompt in reminder, got %q", forwarded)
	}
}

func TestApplyCloaking_FullSystemPromptAuthAttrOptOut(t *testing.T) {
	cfg := &config.Config{}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"cloak_full_system_prompt": "false",
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	out, errCloaking := applyCloaking(context.Background(), cfg, auth, payload, "claude-3-5-sonnet-20241022", "")
	if errCloaking != nil {
		t.Fatalf("applyCloaking() error = %v", errCloaking)
	}
	if got := len(gjson.GetBytes(out, "system").Array()); got != 2 {
		t.Fatalf("system block count = %d, want 2: %s", got, gjson.GetBytes(out, "system").Raw)
	}
}

func TestClaudeExecutor_SDKCLIIdentityFollowsClientEntrypoint(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":    "key-123",
		"base_url":   server.URL,
		"cloak_mode": "always",
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"Reply only OK"}]}]}`)
	ctx := contextWithGinHeaders(map[string]string{"User-Agent": "claude-cli/2.1.216 (external, sdk-cli)"})

	_, err := executor.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if got, want := gjson.GetBytes(seenBody, "system.0.text").String(), "x-anthropic-billing-header: cc_version=2.1.216.859; cc_entrypoint=sdk-cli;"; got != want {
		t.Fatalf("billing header = %q, want %q", got, want)
	}
	if got, want := gjson.GetBytes(seenBody, "system.1.text").String(), "You are a Claude agent, built on Anthropic's Claude Agent SDK."; got != want {
		t.Fatalf("sdk-cli identity = %q, want %q", got, want)
	}
	if gjson.GetBytes(seenBody, "system.1.cache_control").Exists() {
		t.Fatalf("sdk-cli identity must not include cache_control: %s", gjson.GetBytes(seenBody, "system.1").Raw)
	}
	if got := seenHeaders.Get("Anthropic-Dangerous-Direct-Browser-Access"); got != "true" {
		t.Fatalf("Anthropic-Dangerous-Direct-Browser-Access = %q, want true", got)
	}
	if got := seenHeaders.Get("Accept"); got != "application/json" {
		t.Fatalf("Accept = %q, want application/json", got)
	}
	if got := seenHeaders.Get("Accept-Encoding"); got != "gzip, deflate, br, zstd" {
		t.Fatalf("Accept-Encoding = %q, want gzip, deflate, br, zstd", got)
	}
	userID := gjson.GetBytes(seenBody, "metadata.user_id").String()
	assertClaudeCodeMetadataUserID(t, userID)
	if got, want := gjson.Get(userID, "session_id").String(), seenHeaders.Get("X-Claude-Code-Session-Id"); got != want {
		t.Fatalf("metadata.user_id.session_id = %q, want X-Claude-Code-Session-Id %q", got, want)
	}
	if got := gjson.GetBytes(seenBody, "messages.0.content.0.cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("current user prompt cache_control.type = %q, want ephemeral; body=%s", got, string(seenBody))
	}
}

func TestClaudeExecutor_AppliesPayloadRulesBeforeBuildingCloakEnvelope(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{
		Models: []config.PayloadModelRule{{Name: "claude-3-5-sonnet-20241022", Protocol: "claude"}},
		Params: map[string]any{
			"model":                     "claude-opus-4-6",
			"messages.0.content.0.text": "after override",
			"system":                    []map[string]any{{"type": "text", "text": "customer policy"}},
			"tools":                     []map[string]any{{"name": "bash", "input_schema": map[string]any{"type": "object"}}},
		},
	}}}})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":    "key-123",
		"base_url":   server.URL,
		"cloak_mode": "always",
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"before override"}]}],"system":[{"type":"text","text":"old policy"}],"tools":[]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model: "claude-3-5-sonnet-20241022", Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if got := gjson.GetBytes(seenBody, "model").String(); got != "claude-opus-4-6" {
		t.Fatalf("upstream model = %q, want payload override", got)
	}
	wantBilling := "x-anthropic-billing-header: cc_version=2.1.216." + computeFingerprint("after override", "2.1.216") + "; cc_entrypoint=sdk-cli;"
	if got := gjson.GetBytes(seenBody, "system.0.text").String(); got != wantBilling {
		t.Fatalf("billing header was derived from stale body\ngot:  %q\nwant: %q", got, wantBilling)
	}
	if got, want := gjson.GetBytes(seenBody, "system.2.text").String(), helps.ClaudeCodeStaticSystemPromptForTools(true, false, false); got != want {
		t.Fatalf("system[2] did not follow overridden tools")
	}
	if forwarded := gjson.GetBytes(seenBody, "messages.0.content.0.text").String(); !strings.Contains(forwarded, "customer policy") || strings.Contains(forwarded, "old policy") {
		t.Fatalf("cloak did not consume final overridden system: %q", forwarded)
	}
	if got := gjson.GetBytes(seenBody, "messages.0.content.1.text").String(); got != "after override" {
		t.Fatalf("final user text = %q, want after override", got)
	}
}

func TestClaudeExecutor_CustomBaseDoesNotEnableCCHByDefault(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}

	billingHeader := gjson.GetBytes(seenBody, "system.0.text").String()
	if !strings.HasPrefix(billingHeader, "x-anthropic-billing-header:") {
		t.Fatalf("system.0.text = %q, want billing header", billingHeader)
	}
	if !strings.Contains(billingHeader, "cc_version=2.1.216.") {
		t.Fatalf("billing header should use Claude Code 2.1.216, got %q", billingHeader)
	}
	if strings.Contains(billingHeader, " cch=") {
		t.Fatalf("custom base URL should not receive cch by default, got %q", billingHeader)
	}
}

func TestClaudeExecutor_FirstPartyAPIKeyDoesNotSignCCHByDefault(t *testing.T) {
	var seenBody []byte
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.URL.String(); got != "https://api.anthropic.com/v1/messages?beta=true" {
			t.Fatalf("upstream URL = %q", got)
		}
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatalf("read upstream body: %v", errRead)
		}
		seenBody = bytes.Clone(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`)),
			Request:    req,
		}, nil
	}))

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Provider: "claude", Attributes: map[string]string{"api_key": "key-123"}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, errExecute := executor.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
		Headers:      http.Header{"User-Agent": {"third-party-client/1.0"}},
	})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	billingHeader := gjson.GetBytes(seenBody, "system.0.text").String()
	if !strings.HasPrefix(billingHeader, "x-anthropic-billing-header:") {
		t.Fatalf("system.0.text = %q, want billing header", billingHeader)
	}
	if strings.Contains(billingHeader, " cch=") {
		t.Fatalf("first-party API-key requests must not receive cch by default: %s", seenBody)
	}
}

func TestClaudeExecutor_DeprecatedCCHFlagDoesNotOverrideCustomBaseGate(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey:                 "key-123",
			BaseURL:                server.URL,
			ExperimentalCCHSigning: true,
		}},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	const messageText = "please keep literal cch=00000 in this message"
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"please keep literal cch=00000 in this message"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if got := gjson.GetBytes(seenBody, "messages.0.content.0.text").String(); got != messageText {
		t.Fatalf("message text = %q, want %q", got, messageText)
	}

	billingHeader := gjson.GetBytes(seenBody, "system.0.text").String()
	if strings.Contains(billingHeader, " cch=") {
		t.Fatalf("deprecated cch flag must not enable signing for a custom base URL: %s", seenBody)
	}
}

func TestClaudeExecutor_RebuildMidSystemMessageDisabledByDefault(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey:  "key-123",
			BaseURL: server.URL,
		}},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"system":[{"type":"text","text":"Top rule","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]},{"role":"system","content":"Mid rule"},{"role":"user","content":[{"type":"text","text":"continue"}]}]}`)
	ctx := contextWithGinHeaders(map[string]string{"User-Agent": "claude-cli/2.1.153 (external, cli)"})

	_, errExecute := executor.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if got := gjson.GetBytes(seenBody, "system.0.text").String(); got != "Top rule" {
		t.Fatalf("system.0.text = %q, want top-level system preserved", got)
	}
	if got := gjson.GetBytes(seenBody, `messages.#(role=="system").content`).String(); got != "Mid rule" {
		t.Fatalf("mid system message = %q, want original message preserved", got)
	}
}

func TestClaudeExecutor_RebuildMidSystemMessageOptInMovesSystemMessages(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey:                  "key-123",
			BaseURL:                 server.URL,
			RebuildMidSystemMessage: true,
		}},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"system":"Top rule","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]},{"role":"system","content":"Mid string rule"},{"role":"assistant","content":[{"type":"text","text":"ok"}]},{"role":"system","content":[{"type":"text","text":"Mid array rule","cache_control":{"type":"ephemeral"}}]},{"role":"user","content":[{"type":"text","text":"continue"}]}]}`)
	ctx := contextWithGinHeaders(map[string]string{"User-Agent": "claude-cli/2.1.153 (external, cli)"})

	_, errExecute := executor.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}

	system := gjson.GetBytes(seenBody, "system").Array()
	if len(system) != 3 {
		t.Fatalf("system has %d items, want 3: %s", len(system), gjson.GetBytes(seenBody, "system").Raw)
	}
	wantTexts := []string{"Top rule", "Mid string rule", "Mid array rule"}
	for i, want := range wantTexts {
		if got := system[i].Get("text").String(); got != want {
			t.Fatalf("system[%d].text = %q, want %q", i, got, want)
		}
	}
	if got := gjson.GetBytes(seenBody, "system.2.cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("system.2.cache_control.type = %q, want ephemeral", got)
	}
	if gjson.GetBytes(seenBody, `messages.#(role=="system")`).Exists() {
		t.Fatalf("messages should not contain system role after rebuild: %s", gjson.GetBytes(seenBody, "messages").Raw)
	}
	if got := gjson.GetBytes(seenBody, "messages.#").Int(); got != 3 {
		t.Fatalf("messages count = %d, want 3", got)
	}
}

func TestApplyCloaking_PreservesConfiguredStrictModeAndSensitiveWordsWhenModeOmitted(t *testing.T) {
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "key-123",
			Cloak: &config.CloakConfig{
				StrictMode:     true,
				SensitiveWords: []string{"proxy"},
			},
		}},
	}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-123"}}
	payload := []byte(`{"system":"proxy rules","messages":[{"role":"user","content":[{"type":"text","text":"proxy access"}]}]}`)

	out, errCloaking := applyCloaking(context.Background(), cfg, auth, payload, "claude-3-5-sonnet-20241022", "key-123")
	if errCloaking != nil {
		t.Fatalf("applyCloaking() error = %v", errCloaking)
	}

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 4 {
		t.Fatalf("expected strict mode to keep the 4 injected Claude Code system blocks, got %d", len(blocks))
	}
	if got := gjson.GetBytes(out, "messages.0.content.#").Int(); got != 1 {
		t.Fatalf("strict mode should not prepend a forwarded system reminder block, got %d content blocks", got)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.text").String(); !strings.Contains(got, "\u200B") {
		t.Fatalf("expected configured sensitive word obfuscation to apply, got %q", got)
	}
}

func TestApplyCloaking_FullSystemPromptDefaultEnabled(t *testing.T) {
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "key-123",
		}},
	}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-123"}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	out, errCloaking := applyCloaking(context.Background(), cfg, auth, payload, "claude-3-5-sonnet-20241022", "key-123")
	if errCloaking != nil {
		t.Fatalf("applyCloaking() error = %v", errCloaking)
	}

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 4 {
		t.Fatalf("system block count = %d, want 4: %s", len(blocks), gjson.GetBytes(out, "system").Raw)
	}
	if !strings.Contains(blocks[2].Get("text").String(), "# Doing tasks") {
		t.Fatalf("full static prompt missing Doing tasks section: %q", blocks[2].Get("text").String())
	}
	if got := blocks[2].Get("cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("full static prompt cache_control.type = %q, want ephemeral", got)
	}
}

func TestApplyCloaking_FullSystemPromptConfigOptOutOverridesAuthAttr(t *testing.T) {
	fullSystemPrompt := false
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "key-123",
			Cloak: &config.CloakConfig{
				FullSystemPrompt: &fullSystemPrompt,
			},
		}},
	}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":                  "key-123",
		"cloak_full_system_prompt": "true",
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	out, errCloaking := applyCloaking(context.Background(), cfg, auth, payload, "claude-3-5-sonnet-20241022", "key-123")
	if errCloaking != nil {
		t.Fatalf("applyCloaking() error = %v", errCloaking)
	}
	if got := len(gjson.GetBytes(out, "system").Array()); got != 2 {
		t.Fatalf("system block count = %d, want 2: %s", got, gjson.GetBytes(out, "system").Raw)
	}
}

func TestNormalizeClaudeSamplingForUpstream_RemovesTemperature(t *testing.T) {
	payload := []byte(`{"temperature":0,"thinking":{"type":"adaptive"},"output_config":{"effort":"max"}}`)
	out := normalizeClaudeSamplingForUpstream(payload)

	if gjson.GetBytes(out, "temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
}

func TestNormalizeClaudeSamplingForUpstream_RemovesTemperatureWithThinkingEnabled(t *testing.T) {
	payload := []byte(`{"temperature":0.2,"thinking":{"type":"enabled","budget_tokens":2048}}`)
	out := normalizeClaudeSamplingForUpstream(payload)

	if gjson.GetBytes(out, "temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
}

func TestNormalizeClaudeSamplingForUpstream_RemovesTopPAndTopKForThinking(t *testing.T) {
	payload := []byte(`{"temperature":0.2,"top_p":0.9,"top_k":40,"thinking":{"type":"adaptive"}}`)
	out := normalizeClaudeSamplingForUpstream(payload)

	if gjson.GetBytes(out, "temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
	if gjson.GetBytes(out, "top_p").Exists() {
		t.Fatalf("top_p should be removed when thinking is active")
	}
	if gjson.GetBytes(out, "top_k").Exists() {
		t.Fatalf("top_k should be removed when thinking is active")
	}
}

func TestNormalizeClaudeSamplingForUpstream_NoThinkingRemovesTemperatureAndTopP(t *testing.T) {
	payload := []byte(`{"temperature":0,"top_p":0.9,"top_k":40,"messages":[{"role":"user","content":"hi"}]}`)
	out := normalizeClaudeSamplingForUpstream(payload)

	if gjson.GetBytes(out, "temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
	if gjson.GetBytes(out, "top_p").Exists() {
		t.Fatalf("top_p should be removed")
	}
	if got := gjson.GetBytes(out, "top_k").Int(); got != 40 {
		t.Fatalf("top_k = %v, want 40", got)
	}
}

func TestNormalizeClaudeSamplingForUpstream_AfterForcedToolChoiceRemovesTemperature(t *testing.T) {
	payload := []byte(`{"temperature":0,"thinking":{"type":"adaptive"},"output_config":{"effort":"max"},"tool_choice":{"type":"any"}}`)
	out := disableThinkingIfToolChoiceForced(payload)
	out = normalizeClaudeSamplingForUpstream(out)

	if gjson.GetBytes(out, "thinking").Exists() {
		t.Fatalf("thinking should be removed when tool_choice forces tool use")
	}
	if gjson.GetBytes(out, "temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
}

func TestRemapOAuthToolNames_TitleCase_NoReverseNeeded(t *testing.T) {
	body := []byte(`{"tools":[{"name":"Bash","description":"Run shell commands","input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	out, reverseMap := remapOAuthToolNames(body)
	if len(reverseMap) != 0 {
		t.Fatalf("reverseMap = %v, want empty", reverseMap)
	}
	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "Bash" {
		t.Fatalf("tools.0.name = %q, want %q", got, "Bash")
	}

	resp := []byte(`{"content":[{"type":"tool_use","id":"toolu_01","name":"Bash","input":{"cmd":"ls"}}]}`)
	reversed := reverseRemapOAuthToolNames(resp, reverseMap)
	if got := gjson.GetBytes(reversed, "content.0.name").String(); got != "Bash" {
		t.Fatalf("content.0.name = %q, want %q", got, "Bash")
	}
}

func TestRemapOAuthToolNames_Lowercase_ReverseApplied(t *testing.T) {
	body := []byte(`{"tools":[{"name":"bash","description":"Run shell commands","input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	out, reverseMap := remapOAuthToolNames(body)
	if reverseMap["Bash"] != "bash" {
		t.Fatalf("reverseMap = %v, want entry Bash->bash", reverseMap)
	}
	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "Bash" {
		t.Fatalf("tools.0.name = %q, want %q", got, "Bash")
	}

	resp := []byte(`{"content":[{"type":"tool_use","id":"toolu_01","name":"Bash","input":{"cmd":"ls"}}]}`)
	reversed := reverseRemapOAuthToolNames(resp, reverseMap)
	if got := gjson.GetBytes(reversed, "content.0.name").String(); got != "bash" {
		t.Fatalf("content.0.name = %q, want %q", got, "bash")
	}
}

// TestRemapOAuthToolNames_MixedCase_OnlyRenamedToolsReversed is the regression
// test for a case where a single request contains both a TitleCase tool (which
// must pass through unchanged) and a lowercase tool that we forward-rename.
// Before the fix, triggering ANY forward rename caused the reverse pass to
// lowercase every TitleCase tool in the response using a global reverse map,
// corrupting tool names the client originally sent in TitleCase.
func TestRemapOAuthToolNames_MixedCase_OnlyRenamedToolsReversed(t *testing.T) {
	body := []byte(`{"tools":[` +
		`{"name":"Bash","input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}},` +
		`{"name":"glob","input_schema":{"type":"object","properties":{"filePattern":{"type":"string"}}}}` +
		`]}`)

	out, reverseMap := remapOAuthToolNames(body)

	// Forward: TitleCase `Bash` is not a forward-map key, must pass through.
	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "Bash" {
		t.Fatalf("tools.0.name = %q, want %q (TitleCase tool must not be renamed)", got, "Bash")
	}
	// Forward: `glob` is a forward-map key, upstream sees `Glob`.
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != "Glob" {
		t.Fatalf("tools.1.name = %q, want %q", got, "Glob")
	}

	// Reverse map records ONLY the rename that happened.
	if len(reverseMap) != 1 || reverseMap["Glob"] != "glob" {
		t.Fatalf("reverseMap = %v, want {Glob:glob}", reverseMap)
	}

	// Upstream responds with a `Bash` tool_use. Since we never renamed `Bash`,
	// reverseRemap MUST leave it alone.
	bashResp := []byte(`{"content":[{"type":"tool_use","id":"toolu_01","name":"Bash","input":{"cmd":"ls"}}]}`)
	reversed := reverseRemapOAuthToolNames(bashResp, reverseMap)
	if got := gjson.GetBytes(reversed, "content.0.name").String(); got != "Bash" {
		t.Fatalf("content.0.name = %q, want %q (Bash must be preserved; was never forward-renamed)", got, "Bash")
	}

	// Upstream responds with a `Glob` tool_use. Since we renamed `glob`→`Glob`,
	// reverseRemap MUST restore the original `glob`.
	globResp := []byte(`{"content":[{"type":"tool_use","id":"toolu_02","name":"Glob","input":{"filePattern":"**/*.go"}}]}`)
	reversed = reverseRemapOAuthToolNames(globResp, reverseMap)
	if got := gjson.GetBytes(reversed, "content.0.name").String(); got != "glob" {
		t.Fatalf("content.0.name = %q, want %q (Glob must be restored to client's original `glob`)", got, "glob")
	}
}

func TestRemapOAuthToolNames_DoesNotCollapseAliasOntoExistingOfficialName(t *testing.T) {
	body := []byte(`{"tools":[` +
		`{"name":"bash"},{"name":"Bash"},{"name":"taskcreate"},{"name":"TaskCreate"},{"name":"glob"}` +
		`],"tool_choice":{"type":"tool","name":"bash"},"messages":[{"role":"assistant","content":[` +
		`{"type":"tool_use","name":"bash"},{"type":"tool_use","name":"Bash"},` +
		`{"type":"tool_reference","tool_name":"taskcreate"},{"type":"tool_reference","tool_name":"TaskCreate"}` +
		`]}]}`)

	out, reverseMap := remapOAuthToolNames(body)
	wantNames := []string{"bash", "Bash", "taskcreate", "TaskCreate", "Glob"}
	for i, want := range wantNames {
		if got := gjson.GetBytes(out, fmt.Sprintf("tools.%d.name", i)).String(); got != want {
			t.Fatalf("tools.%d.name = %q, want %q; body=%s", i, got, want, out)
		}
	}
	if got := gjson.GetBytes(out, "tool_choice.name").String(); got != "bash" {
		t.Fatalf("colliding tool_choice name = %q, want bash", got)
	}
	if len(reverseMap) != 1 || reverseMap["Glob"] != "glob" {
		t.Fatalf("reverseMap = %v, want only Glob->glob", reverseMap)
	}
	for path, want := range map[string]string{
		"messages.0.content.0.name":      "bash",
		"messages.0.content.1.name":      "Bash",
		"messages.0.content.2.tool_name": "taskcreate",
		"messages.0.content.3.tool_name": "TaskCreate",
	} {
		if got := gjson.GetBytes(out, path).String(); got != want {
			t.Fatalf("%s = %q, want %q", path, got, want)
		}
	}
}

func TestRemapOAuthToolNamesMapsToolSearchAcrossRequestAndResponse(t *testing.T) {
	body := []byte(`{"tools":[{"name":"tool_search"}],"tool_choice":{"type":"tool","name":"tool_search"},"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"tool_search"},{"type":"tool_reference","tool_name":"tool_search"}]}]}`)
	out, reverseMap := remapOAuthToolNames(body)
	for _, path := range []string{"tools.0.name", "tool_choice.name", "messages.0.content.0.name", "messages.0.content.1.tool_name"} {
		if got := gjson.GetBytes(out, path).String(); got != "ToolSearch" {
			t.Fatalf("%s = %q, want ToolSearch; body=%s", path, got, out)
		}
	}
	if reverseMap["ToolSearch"] != "tool_search" {
		t.Fatalf("reverseMap = %#v", reverseMap)
	}
	response := reverseRemapOAuthToolNames([]byte(`{"content":[{"type":"tool_use","name":"ToolSearch"}]}`), reverseMap)
	if got := gjson.GetBytes(response, "content.0.name").String(); got != "tool_search" {
		t.Fatalf("restored ToolSearch = %q", got)
	}
}

func TestRemapOAuthToolNamesDoesNotCollapseToolSearchAliases(t *testing.T) {
	body := []byte(`{"tools":[{"name":"toolsearch"},{"name":"tool_search"}]}`)
	out, reverseMap := remapOAuthToolNames(body)
	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "toolsearch" {
		t.Fatalf("tools.0.name = %q", got)
	}
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != "tool_search" {
		t.Fatalf("tools.1.name = %q", got)
	}
	if len(reverseMap) != 0 {
		t.Fatalf("reverseMap = %#v, want empty", reverseMap)
	}
}

// TestReverseRemapOAuthToolNamesFromStreamLine_HonorsPerRequestMap guards the
// SSE streaming code path against the same mixed-case bug.
func TestReverseRemapOAuthToolNamesFromStreamLine_HonorsPerRequestMap(t *testing.T) {
	reverseMap := map[string]string{"Glob": "glob"}

	// Bash block was never renamed, must pass through as-is.
	bashLine := []byte(`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"Bash","input":{}}}`)
	out := reverseRemapOAuthToolNamesFromStreamLine(bashLine, reverseMap)
	if !bytes.Contains(out, []byte(`"name":"Bash"`)) {
		t.Fatalf("Bash should be preserved, got: %s", string(out))
	}
	if bytes.Contains(out, []byte(`"name":"bash"`)) {
		t.Fatalf("Bash must not be lowercased, got: %s", string(out))
	}

	// Glob block IS in the reverseMap, must be restored to `glob`.
	globLine := []byte(`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_02","name":"Glob","input":{}}}`)
	out = reverseRemapOAuthToolNamesFromStreamLine(globLine, reverseMap)
	if !bytes.Contains(out, []byte(`"name":"glob"`)) {
		t.Fatalf("Glob should be restored to glob, got: %s", string(out))
	}
}

func TestPrepareClaudeOAuthToolNamesForUpstream_MixedCaseWithPrefix(t *testing.T) {
	body := []byte(`{"tools":[` +
		`{"name":"Bash","input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}},` +
		`{"name":"glob","input_schema":{"type":"object","properties":{"filePattern":{"type":"string"}}}}` +
		`],"messages":[{"role":"assistant","content":[` +
		`{"type":"tool_use","id":"toolu_01","name":"Bash","input":{}},` +
		`{"type":"tool_use","id":"toolu_02","name":"glob","input":{}}` +
		`]}]}`)

	out, reverseMap := prepareClaudeOAuthToolNamesForUpstream(body, "proxy_", false)

	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "proxy_Bash" {
		t.Fatalf("tools.0.name = %q, want %q", got, "proxy_Bash")
	}
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != "proxy_Glob" {
		t.Fatalf("tools.1.name = %q, want %q", got, "proxy_Glob")
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.name").String(); got != "proxy_Bash" {
		t.Fatalf("messages.0.content.0.name = %q, want %q", got, "proxy_Bash")
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.name").String(); got != "proxy_Glob" {
		t.Fatalf("messages.0.content.1.name = %q, want %q", got, "proxy_Glob")
	}
	if len(reverseMap) != 1 || reverseMap["Glob"] != "glob" {
		t.Fatalf("reverseMap = %v, want {Glob:glob}", reverseMap)
	}
}

func TestRestoreClaudeOAuthToolNamesFromResponse_MixedCaseWithPrefix(t *testing.T) {
	reverseMap := map[string]string{"Glob": "glob"}
	resp := []byte(`{"content":[` +
		`{"type":"tool_use","id":"toolu_01","name":"proxy_Bash","input":{}},` +
		`{"type":"tool_use","id":"toolu_02","name":"proxy_Glob","input":{}}` +
		`]}`)

	out := restoreClaudeOAuthToolNamesFromResponse(resp, "proxy_", false, reverseMap)

	if got := gjson.GetBytes(out, "content.0.name").String(); got != "Bash" {
		t.Fatalf("content.0.name = %q, want %q", got, "Bash")
	}
	if got := gjson.GetBytes(out, "content.1.name").String(); got != "glob" {
		t.Fatalf("content.1.name = %q, want %q", got, "glob")
	}
}

func TestRestoreClaudeOAuthToolNamesFromStreamLine_MixedCaseWithPrefix(t *testing.T) {
	reverseMap := map[string]string{"Glob": "glob"}

	bashLine := []byte(`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"proxy_Bash","input":{}}}`)
	out := restoreClaudeOAuthToolNamesFromStreamLine(bashLine, "proxy_", false, reverseMap)
	if !bytes.Contains(out, []byte(`"name":"Bash"`)) {
		t.Fatalf("Bash should be preserved, got: %s", string(out))
	}
	if bytes.Contains(out, []byte(`"name":"bash"`)) {
		t.Fatalf("Bash must not be lowercased, got: %s", string(out))
	}

	globLine := []byte(`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_02","name":"proxy_Glob","input":{}}}`)
	out = restoreClaudeOAuthToolNamesFromStreamLine(globLine, "proxy_", false, reverseMap)
	if !bytes.Contains(out, []byte(`"name":"glob"`)) {
		t.Fatalf("Glob should be restored to glob, got: %s", string(out))
	}
}

func TestEnsureClaudeThinkingDisplay_SetsSummarizedWhenMissing(t *testing.T) {
	payload := []byte(`{"thinking":{"type":"adaptive"},"output_config":{"effort":"high"}}`)
	out := ensureClaudeThinkingDisplay(payload)

	if got := gjson.GetBytes(out, "thinking.display").String(); got != "summarized" {
		t.Fatalf("thinking.display = %q, want summarized", got)
	}
	if got := gjson.GetBytes(out, "thinking.type").String(); got != "adaptive" {
		t.Fatalf("thinking.type = %q, want adaptive", got)
	}
}

func TestEnsureClaudeThinkingDisplay_PreservesExplicitValue(t *testing.T) {
	payload := []byte(`{"thinking":{"type":"enabled","budget_tokens":2048,"display":"omitted"}}`)
	out := ensureClaudeThinkingDisplay(payload)

	if got := gjson.GetBytes(out, "thinking.display").String(); got != "omitted" {
		t.Fatalf("thinking.display = %q, want omitted", got)
	}
}

func TestEnsureClaudeThinkingDisplay_SkipsWhenThinkingDisabled(t *testing.T) {
	payload := []byte(`{"thinking":{"type":"disabled"}}`)
	out := ensureClaudeThinkingDisplay(payload)

	if gjson.GetBytes(out, "thinking.display").Exists() {
		t.Fatalf("thinking.display should not be set when thinking is disabled: %s", out)
	}
}

func TestEnsureClaudeThinkingDisplay_SkipsWhenThinkingMissing(t *testing.T) {
	payload := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	out := ensureClaudeThinkingDisplay(payload)

	if gjson.GetBytes(out, "thinking").Exists() {
		t.Fatalf("thinking should remain absent: %s", out)
	}
}

func TestEnsureClaudeCodeContextManagementMatchesThinkingState(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantInject bool
	}{
		{name: "enabled", body: `{"thinking":{"type":"enabled","budget_tokens":1024}}`, wantInject: true},
		{name: "adaptive", body: `{"thinking":{"type":"adaptive"}}`, wantInject: true},
		{name: "disabled", body: `{"thinking":{"type":"disabled"}}`},
		{name: "auto is not an upstream thinking type", body: `{"thinking":{"type":"auto"}}`},
		{name: "missing", body: `{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := ensureClaudeCodeContextManagement([]byte(test.body))
			if got := gjson.GetBytes(out, "context_management").Exists(); got != test.wantInject {
				t.Fatalf("context_management exists = %t, want %t: %s", got, test.wantInject, out)
			}
			if test.wantInject {
				if got := gjson.GetBytes(out, "context_management.edits.0.type").String(); got != "clear_thinking_20251015" {
					t.Fatalf("context management type = %q", got)
				}
				if got := gjson.GetBytes(out, "context_management.edits.0.keep").String(); got != "all" {
					t.Fatalf("context management keep = %q", got)
				}
			}
		})
	}
}

func TestEnsureClaudeCodeContextManagementPreservesClientValue(t *testing.T) {
	payload := []byte(`{"thinking":{"type":"adaptive"},"context_management":{"edits":[{"type":"custom_edit","keep":"none"}]}}`)
	if got := ensureClaudeCodeContextManagement(payload); !bytes.Equal(got, payload) {
		t.Fatalf("explicit client context_management changed:\ngot:  %s\nwant: %s", got, payload)
	}
}

func TestEnsureClaudeCodeToolsArrayAddsOnlyAnEmptyArray(t *testing.T) {
	payload := []byte(`{"tool_choice":{"type":"any"},"messages":[]}`)
	out := ensureClaudeCodeToolsArray(payload)
	if got := gjson.GetBytes(out, "tools").Raw; got != "[]" {
		t.Fatalf("tools = %s, want []", got)
	}
	if gjson.GetBytes(out, "tools.0").Exists() {
		t.Fatalf("synthetic executable tool was injected: %s", out)
	}

	explicit := []byte(`{"tools":[{"name":"client_tool","input_schema":{"type":"object"}}]}`)
	if got := ensureClaudeCodeToolsArray(explicit); !bytes.Equal(got, explicit) {
		t.Fatalf("client tools changed:\ngot:  %s\nwant: %s", got, explicit)
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileDefaultsAdaptiveAndPreservesExtraBodySampling(t *testing.T) {
	payload := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"temperature":0.7,"top_p":0.9,"top_k":40}`)
	out := prepareClaudeCloakedThinking(payload, "claude-sonnet-4-6", true)
	if got := gjson.GetBytes(out, "thinking.type").String(); got != "adaptive" {
		t.Fatalf("thinking.type = %q, want adaptive: %s", got, out)
	}
	if gjson.GetBytes(out, "thinking.display").Exists() {
		t.Fatalf("default synthetic profile must leave thinking.display to the API default: %s", out)
	}
	if got := len(gjson.GetBytes(out, "thinking").Map()); got != 1 {
		t.Fatalf("captured adaptive thinking shape must contain only type: %s", out)
	}
	if got := gjson.GetBytes(out, "output_config.effort").String(); got != "high" {
		t.Fatalf("output_config.effort = %q, want high: %s", got, out)
	}
	for path, want := range map[string]float64{"temperature": 0.7, "top_p": 0.9, "top_k": 40} {
		if got := gjson.GetBytes(out, path).Float(); got != want {
			t.Fatalf("%s = %v, want explicit extra-body value %v: %s", path, got, want, out)
		}
	}
}

func TestApplySyntheticClaudeCodeThinkingProfilePreservesExplicitValues(t *testing.T) {
	payload := []byte(`{"thinking":{"type":"adaptive","display":"summarized"},"output_config":{"effort":"low"}}`)
	out := prepareClaudeCloakedThinking(payload, "claude-opus-4-6", true)
	if got := gjson.GetBytes(out, "thinking.display").String(); got != "summarized" {
		t.Fatalf("explicit display = %q, want summarized", got)
	}
	if got := gjson.GetBytes(out, "output_config.effort").String(); got != "low" {
		t.Fatalf("explicit effort = %q, want low", got)
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileDemotesForcedToolChoice(t *testing.T) {
	payload := []byte(`{"tool_choice":{"type":"tool","name":"Bash"}}`)
	out := prepareClaudeCloakedThinking(payload, "claude-sonnet-4-6", true)
	if got := gjson.GetBytes(out, "tool_choice.type").String(); got != "auto" {
		t.Fatalf("tool_choice.type = %q, want auto: %s", got, out)
	}
	if got := gjson.GetBytes(out, "thinking.type").String(); got != "adaptive" {
		t.Fatalf("thinking.type = %q, want adaptive: %s", got, out)
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileMatchesOfficialLegacyDefault(t *testing.T) {
	models := map[string]string{
		"claude-sonnet-4-5-20250929": "",
		"claude-opus-4-5-20251101":   "high",
		"claude-haiku-4-5-20251001":  "",
	}
	for model, wantEffort := range models {
		t.Run(model, func(t *testing.T) {
			payload := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
			payload = ensureClaudeCodeMaxTokens(payload, model)
			out := prepareClaudeCloakedThinking(payload, model, true)
			if got := gjson.GetBytes(out, "thinking.type").String(); got != "enabled" {
				t.Fatalf("thinking.type = %q, want enabled: %s", got, out)
			}
			if got := gjson.GetBytes(out, "thinking.budget_tokens").Int(); got != 31999 {
				t.Fatalf("thinking.budget_tokens = %d, want 31999: %s", got, out)
			}
			if got := gjson.GetBytes(out, "thinking").Raw; got != `{"budget_tokens":31999,"type":"enabled"}` {
				t.Fatalf("thinking raw object = %s, want native budget_tokens/type order", got)
			}
			if gjson.GetBytes(out, "thinking.display").Exists() {
				t.Fatalf("default synthetic profile must leave thinking.display to the API default: %s", out)
			}
			if gotEffort := gjson.GetBytes(out, "output_config.effort").String(); gotEffort != wantEffort {
				t.Fatalf("output_config.effort = %q, want %q: %s", gotEffort, wantEffort, out)
			}
			if gjson.GetBytes(out, "temperature").Exists() {
				t.Fatalf("legacy active thinking leaked temperature: %s", out)
			}
		})
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileLegacyOrderPreservesExplicitFields(t *testing.T) {
	payload := []byte(`{"max_tokens":32000,"thinking":{"display":"omitted","type":"enabled","budget_tokens":4096,"customer_key":{"keep":true}}}`)
	out := prepareClaudeCloakedThinking(payload, "claude-sonnet-4-5-20250929", true)
	if got := gjson.GetBytes(out, "thinking").Raw; got != `{"budget_tokens":4096,"type":"enabled","display":"omitted","customer_key":{"keep":true}}` {
		t.Fatalf("thinking raw object = %s, want native leading keys with explicit fields retained", got)
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileCanonicalizesAdaptiveOnlyModels(t *testing.T) {
	for _, model := range []string{
		"claude-opus-4-7",
		"claude-opus-4-8",
		"claude-sonnet-5",
		"claude-fable-5",
		"claude-mythos-5",
	} {
		t.Run(model, func(t *testing.T) {
			payload := []byte(`{"thinking":{"type":"enabled","budget_tokens":2048,"display":"omitted","customer_key":"keep"}}`)
			out := prepareClaudeCloakedThinking(payload, model, true)
			if got := gjson.GetBytes(out, "thinking.type").String(); got != "adaptive" {
				t.Fatalf("thinking.type = %q, want adaptive: %s", got, out)
			}
			if gjson.GetBytes(out, "thinking.budget_tokens").Exists() {
				t.Fatalf("adaptive-only model retained budget_tokens: %s", out)
			}
			if got := gjson.GetBytes(out, "thinking.display").String(); got != "omitted" {
				t.Fatalf("thinking.display = %q, want explicit omitted: %s", got, out)
			}
			if got := gjson.GetBytes(out, "thinking.customer_key").String(); got != "keep" {
				t.Fatalf("thinking.customer_key = %q, want preserved: %s", got, out)
			}
		})
	}

	legacyCompatible := prepareClaudeCloakedThinking(
		[]byte(`{"thinking":{"type":"enabled","budget_tokens":2048}}`),
		"claude-sonnet-4-6",
		true,
	)
	if got := gjson.GetBytes(legacyCompatible, "thinking.type").String(); got != "enabled" {
		t.Fatalf("Sonnet 4.6 explicit legacy thinking type = %q, want enabled: %s", got, legacyCompatible)
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileMatchesOfficialLegacyBudgetClampOrder(t *testing.T) {
	for name, payload := range map[string]string{
		"small max tokens":         `{"max_tokens":100}`,
		"negative explicit budget": `{"max_tokens":32000,"thinking":{"type":"enabled","budget_tokens":-1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			out := prepareClaudeCloakedThinking([]byte(payload), "claude-sonnet-4-5-20250929", true)
			if got := gjson.GetBytes(out, "thinking.budget_tokens").Int(); got != 1024 {
				t.Fatalf("thinking.budget_tokens = %d, want official clamp floor 1024: %s", got, out)
			}
		})
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileMatchesOfficialDisabledProfile(t *testing.T) {
	payload := []byte(`{"thinking":{"type":"disabled","display":"summarized","budget_tokens":4096,"customer_key":"keep-me-out"},"top_p":0.9,"top_k":40}`)
	out := prepareClaudeCloakedThinking(payload, "claude-opus-4-6", true)
	if got := gjson.GetBytes(out, "thinking.type").String(); got != "disabled" {
		t.Fatalf("thinking.type = %q, want disabled: %s", got, out)
	}
	if gjson.GetBytes(out, "thinking.display").Exists() {
		t.Fatalf("disabled thinking retained display: %s", out)
	}
	if got := len(gjson.GetBytes(out, "thinking").Map()); got != 1 {
		t.Fatalf("disabled thinking was not canonicalized to the type sentinel: %s", out)
	}
	if got := gjson.GetBytes(out, "temperature").Int(); got != 1 {
		t.Fatalf("temperature = %d, want 1: %s", got, out)
	}
	if got := gjson.GetBytes(out, "output_config.effort").String(); got != "high" {
		t.Fatalf("output_config.effort = %q, want high: %s", got, out)
	}
	for _, path := range []string{"top_p", "top_k"} {
		if !gjson.GetBytes(out, path).Exists() {
			t.Fatalf("explicit extra-body %s was removed: %s", path, out)
		}
	}
	if gjson.GetBytes(ensureClaudeCodeContextManagement(out), "context_management").Exists() {
		t.Fatalf("disabled thinking injected context management: %s", out)
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileOmitsRejectedDisabledSentinel(t *testing.T) {
	for _, model := range []string{"claude-fable-5", "claude-mythos-5", "fixture-custom-model"} {
		t.Run(model, func(t *testing.T) {
			payload := []byte(`{"thinking":{"type":"disabled","display":"summarized"},"tool_choice":{"type":"tool","name":"Bash"}}`)
			out := prepareClaudeCloakedThinking(payload, model, true)
			if gjson.GetBytes(out, "thinking").Exists() {
				t.Fatalf("thinking must be omitted for rejects-disabled model: %s", out)
			}
			if got := gjson.GetBytes(out, "output_config.effort").String(); got != "high" {
				t.Fatalf("output_config.effort = %q, want high: %s", got, out)
			}
			if got := gjson.GetBytes(out, "tool_choice.type").String(); got != "auto" {
				t.Fatalf("tool_choice.type = %q, want auto: %s", got, out)
			}
			if gjson.GetBytes(out, "temperature").Exists() {
				t.Fatalf("rejects-disabled model unexpectedly injected temperature: %s", out)
			}
		})
	}
}

func TestSyntheticClaudeCodeAlwaysAdaptiveDisabledThinkingFullPipeline(t *testing.T) {
	for _, model := range []string{"claude-fable-5", "claude-mythos-5"} {
		t.Run(model, func(t *testing.T) {
			body := []byte(`{"thinking":{"type":"disabled","display":"summarized"},"tool_choice":{"type":"tool","name":"Bash"}}`)
			body, err := thinking.ApplyThinking(body, model, "claude", "claude", "claude")
			if err != nil {
				t.Fatalf("ApplyThinking() error = %v", err)
			}
			body = prepareClaudeCloakedThinking(body, model, true)

			if gjson.GetBytes(body, "thinking").Exists() {
				t.Fatalf("thinking must be omitted after the complete synthetic pipeline: %s", body)
			}
			if got := gjson.GetBytes(body, "output_config.effort").String(); got != "high" {
				t.Fatalf("output_config.effort = %q, want high: %s", got, body)
			}
			if got := gjson.GetBytes(body, "tool_choice.type").String(); got != "auto" {
				t.Fatalf("tool_choice.type = %q, want auto: %s", got, body)
			}
			if gjson.GetBytes(ensureClaudeCodeContextManagement(body), "context_management").Exists() {
				t.Fatalf("disabled thinking injected context management: %s", body)
			}
		})
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileRejectsDisabledKeepsAnyToolChoice(t *testing.T) {
	out := prepareClaudeCloakedThinking([]byte(`{"thinking":{"type":"disabled"},"tool_choice":{"type":"any"}}`), "claude-fable-5", true)
	if gjson.GetBytes(out, "thinking").Exists() {
		t.Fatalf("thinking must be omitted: %s", out)
	}
	if got := gjson.GetBytes(out, "tool_choice.type").String(); got != "any" {
		t.Fatalf("tool_choice.type = %q, want any: %s", got, out)
	}
}

func TestClaudeCodeRejectsDisabledThinkingMatchesOfficialFirstPartyMatrix(t *testing.T) {
	tests := map[string]bool{
		"claude-3-7-sonnet-20250219": false,
		"claude-opus-4-20250514":     false,
		"claude-opus-4-1-20250805":   false,
		"claude-opus-4-5-20251101":   false,
		"claude-opus-4-6":            false,
		"claude-opus-4-7":            false,
		"claude-opus-4-8":            false,
		"claude-sonnet-4-20250514":   false,
		"claude-sonnet-4-5-20250929": false,
		"claude-sonnet-4-6":          false,
		"claude-sonnet-5":            false,
		"claude-haiku-4-5-20251001":  false,
		"claude-fable-5":             true,
		"claude-mythos-5":            true,
		"fixture-custom-model":       true,
	}
	for model, want := range tests {
		if got := claudeCodeRejectsDisabledThinking(model); got != want {
			t.Errorf("claudeCodeRejectsDisabledThinking(%q) = %t, want %t", model, got, want)
		}
	}
}

func TestApplySyntheticClaudeCodeThinkingProfilePreservesInactiveTemperatureOverride(t *testing.T) {
	payload := []byte(`{"thinking":{"type":"disabled"},"temperature":0.25}`)
	out := prepareClaudeCloakedThinking(payload, "claude-sonnet-4-5-20250929", true)
	if got := gjson.GetBytes(out, "temperature").Float(); got != 0.25 {
		t.Fatalf("temperature = %v, want explicit 0.25: %s", got, out)
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileLeavesAnyToolChoice(t *testing.T) {
	payload := []byte(`{"tool_choice":{"type":"any"}}`)
	out := prepareClaudeCloakedThinking(payload, "claude-sonnet-4-6", true)
	if got := gjson.GetBytes(out, "tool_choice.type").String(); got != "any" {
		t.Fatalf("tool_choice.type = %q, want any: %s", got, out)
	}
	if got := gjson.GetBytes(out, "thinking.type").String(); got != "adaptive" {
		t.Fatalf("thinking.type = %q, want adaptive: %s", got, out)
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileClaude3OmitsThinking(t *testing.T) {
	for _, input := range []string{
		`{}`,
		`{"thinking":{"type":"enabled","budget_tokens":4096,"display":"summarized"}}`,
		`{"thinking":{"type":"disabled","display":"omitted"}}`,
	} {
		out := prepareClaudeCloakedThinking([]byte(input), "claude-3-7-sonnet-20250219", true)
		if gjson.GetBytes(out, "thinking").Exists() {
			t.Fatalf("Claude 3 request retained thinking for %s: %s", input, out)
		}
		if got := gjson.GetBytes(out, "temperature").Int(); got != 1 {
			t.Fatalf("temperature = %d, want 1: %s", got, out)
		}
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileHaiku45OmitsDisplay(t *testing.T) {
	payload := []byte(`{"thinking":{"type":"enabled","budget_tokens":4096,"display":"summarized"}}`)
	out := prepareClaudeCloakedThinking(payload, "claude-haiku-4-5-20251001", true)
	if got := gjson.GetBytes(out, "thinking.type").String(); got != "enabled" {
		t.Fatalf("thinking.type = %q, want enabled: %s", got, out)
	}
	if gjson.GetBytes(out, "thinking.display").Exists() {
		t.Fatalf("Haiku 4.5 retained unsupported thinking.display: %s", out)
	}
}

func TestEnsureClaudeCodeMaxTokensMatchesOfficialDefaultsAndClamp(t *testing.T) {
	tests := []struct {
		name  string
		model string
		body  string
		want  int64
	}{
		{name: "Opus 4.6 default", model: "claude-opus-4-6", body: `{}`, want: 64000},
		{name: "Opus 4.8 upper limit", model: "claude-opus-4-8", body: `{"max_tokens":128000}`, want: 128000},
		{name: "Opus override below default", model: "claude-opus-4-6", body: `{"max_tokens":12345}`, want: 12345},
		{name: "Sonnet 4.5 default", model: "claude-sonnet-4-5-20250929", body: `{}`, want: 32000},
		{name: "Sonnet 4.6 override above default", model: "claude-sonnet-4-6", body: `{"max_tokens":64000}`, want: 64000},
		{name: "Sonnet 4.6 upper clamp", model: "claude-sonnet-4-6", body: `{"max_tokens":200000}`, want: 128000},
		{name: "Sonnet 4.5 override above default", model: "claude-sonnet-4-5", body: `{"max_tokens":64000}`, want: 64000},
		{name: "Sonnet 4.5 upper clamp", model: "claude-sonnet-4-5", body: `{"max_tokens":128000}`, want: 64000},
		{name: "Opus 4.1 upper clamp", model: "claude-opus-4-1", body: `{"max_tokens":64000}`, want: 32000},
		{name: "Opus 4.5 upper limit", model: "claude-opus-4-5-20251101", body: `{"max_tokens":64000}`, want: 64000},
		{name: "Opus 4.5 upper clamp", model: "claude-opus-4-5", body: `{"max_tokens":128000}`, want: 64000},
		{name: "Opus 4.0 provider ID upper clamp", model: "claude-opus-4-20250514", body: `{"max_tokens":64000}`, want: 32000},
		{name: "Sonnet 4.0 upper limit", model: "claude-sonnet-4-20250514", body: `{"max_tokens":64000}`, want: 64000},
		{name: "Sonnet 5 default", model: "claude-sonnet-5", body: `{}`, want: 64000},
		{name: "Fable 5 default", model: "claude-fable-5", body: `{}`, want: 64000},
		{name: "Mythos 5 upper limit", model: "claude-mythos-5", body: `{"max_tokens":128000}`, want: 128000},
		{name: "Haiku 4.5 default", model: "claude-haiku-4-5-20251001", body: `{}`, want: 32000},
		{name: "Haiku 3.5 default", model: "claude-3-5-haiku-20241022", body: `{}`, want: 8192},
		{name: "Sonnet 3.5 default", model: "claude-3-5-sonnet-20241022", body: `{}`, want: 8192},
		{name: "Sonnet 3.7 default", model: "claude-3-7-sonnet-20250219", body: `{}`, want: 32000},
		{name: "Sonnet 3 default", model: "claude-3-sonnet-20240229", body: `{}`, want: 8192},
		{name: "Opus 3 default", model: "claude-3-opus-20240229", body: `{}`, want: 4096},
		{name: "Haiku 3 default", model: "claude-3-haiku-20240307", body: `{}`, want: 4096},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := ensureClaudeCodeMaxTokens([]byte(test.body), test.model)
			if got := gjson.GetBytes(out, "max_tokens").Int(); got != test.want {
				t.Fatalf("max_tokens = %d, want %d: %s", got, test.want, out)
			}
		})
	}
	unknown := []byte(`{"messages":[]}`)
	if got := gjson.GetBytes(ensureClaudeCodeMaxTokens(unknown, "fixture-model"), "max_tokens").Int(); got != 32000 {
		t.Fatalf("unknown model max_tokens = %d, want official fallback 32000", got)
	}
	if got := gjson.GetBytes(ensureClaudeCodeMaxTokens([]byte(`{"max_tokens":200000}`), "fixture-model"), "max_tokens").Int(); got != 128000 {
		t.Fatalf("unknown model max_tokens = %d, want official fallback upper limit 128000", got)
	}
}

func TestInjectFakeUserIDReplacesTopLevelMetadata(t *testing.T) {
	const sessionID = "123e4567-e89b-42d3-a456-426614174000"
	ctx := withClaudeCanonicalSessionID(context.Background(), sessionID)
	payload := []byte(`{"metadata":{"user_id":"customer","trace_id":"drop-me","nested":{"also":"drop"}},"messages":[]}`)

	out, err := injectFakeUserID(ctx, payload, "fixture-scope", "", "", false)
	if err != nil {
		t.Fatalf("injectFakeUserID() error = %v", err)
	}
	metadata := gjson.GetBytes(out, "metadata")
	if got := len(metadata.Map()); got != 1 {
		t.Fatalf("metadata field count = %d, want only user_id: %s", got, out)
	}
	if got := gjson.Get(metadata.Get("user_id").String(), "session_id").String(); got != sessionID {
		t.Fatalf("metadata.user_id.session_id = %q, want %q: %s", got, sessionID, out)
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileUnknownModelUsesCurrentDefaults(t *testing.T) {
	payload := ensureClaudeCodeMaxTokens([]byte(`{}`), "fixture-custom-model")
	out := prepareClaudeCloakedThinking(payload, "fixture-custom-model", true)
	if got := gjson.GetBytes(out, "max_tokens").Int(); got != 32000 {
		t.Fatalf("max_tokens = %d, want 32000: %s", got, out)
	}
	if got := gjson.GetBytes(out, "thinking.type").String(); got != "adaptive" {
		t.Fatalf("thinking.type = %q, want adaptive: %s", got, out)
	}
	if got := gjson.GetBytes(out, "output_config.effort").String(); got != "high" {
		t.Fatalf("output_config.effort = %q, want high: %s", got, out)
	}
}

func TestApplySyntheticClaudeCodeThinkingProfileMatchesOfficialEffortMatrix(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{model: "claude-3-7-sonnet-20250219"},
		{model: "claude-opus-4-1-20250805"},
		{model: "claude-opus-4-5-20251101", want: "high"},
		{model: "claude-opus-4-6", want: "high"},
		{model: "claude-opus-4-7", want: "xhigh"},
		{model: "claude-opus-4-8", want: "high"},
		{model: "claude-sonnet-4-5-20250929"},
		{model: "claude-sonnet-4-6", want: "high"},
		{model: "claude-sonnet-5", want: "high"},
		{model: "claude-haiku-4-5-20251001"},
		{model: "claude-fable-5", want: "high"},
		{model: "claude-mythos-5", want: "high"},
		{model: "claude-sonnet-4-9", want: "high"},
		{model: "fixture-custom-model", want: "high"},
	}
	for _, test := range tests {
		t.Run(test.model, func(t *testing.T) {
			out := prepareClaudeCloakedThinking([]byte(`{}`), test.model, true)
			if got := gjson.GetBytes(out, "output_config.effort").String(); got != test.want {
				t.Fatalf("output_config.effort = %q, want %q: %s", got, test.want, out)
			}
		})
	}
}

func TestSyntheticClaudeCodeFutureUnknownModelUsesProviderFallbacks(t *testing.T) {
	out := prepareClaudeCloakedThinking([]byte(`{}`), "claude-sonnet-4-9", true)
	if got := gjson.GetBytes(out, "thinking.type").String(); got != "adaptive" {
		t.Fatalf("thinking.type = %q, want adaptive: %s", got, out)
	}
	if got := gjson.GetBytes(out, "output_config.effort").String(); got != "high" {
		t.Fatalf("output_config.effort = %q, want high: %s", got, out)
	}

	disabled := prepareClaudeCloakedThinking([]byte(`{"thinking":{"type":"disabled"}}`), "claude-sonnet-4-9", true)
	if gjson.GetBytes(disabled, "thinking").Exists() {
		t.Fatalf("future unknown model should omit rejected disabled sentinel: %s", disabled)
	}
	if gjson.GetBytes(disabled, "temperature").Exists() {
		t.Fatalf("future unknown model should not inherit the known Sonnet 4 temperature rule: %s", disabled)
	}
}

func TestShouldApplyClaudeCloakingDistinguishesRealClaudeClient(t *testing.T) {
	if !shouldApplyClaudeCloaking(context.Background(), &config.Config{}, nil) {
		t.Fatal("third-party request should use the cloak profile")
	}
	realHeaders := http.Header{"User-Agent": {"claude-cli/2.1.215 (external, cli)"}}
	realCtx, _ := resolveClaudeClientContext(context.Background(), realHeaders)
	if shouldApplyClaudeCloaking(realCtx, &config.Config{}, nil) {
		t.Fatal("real Claude client should bypass thinking normalization")
	}
}

func TestComputeFingerprintUsesJavaScriptUTF16Indexing(t *testing.T) {
	const message = "abcd😀efghijklmnopqrstuv"
	if got := computeFingerprint(message, "2.1.215"); got != "35d" {
		t.Fatalf("computeFingerprint() = %q, want JavaScript reference 35d", got)
	}
	const selectedSurrogatePair = "aaaa😀😁bbbbbbbbbbbbx"
	if got := computeFingerprint(selectedSurrogatePair, "2.1.215"); got != "f0a" {
		t.Fatalf("computeFingerprint(selected surrogate pair) = %q, want official 2.1.215 capture f0a", got)
	}
}

func TestBuildTextBlockUsesJavaScriptCompatibleEscaping(t *testing.T) {
	block := buildTextBlock(`<system-reminder>one & "two"</system-reminder>`, map[string]string{"type": "ephemeral", "ttl": "1h"})
	if strings.Contains(block, `\u003c`) || strings.Contains(block, `\u003e`) || strings.Contains(block, `\u0026`) {
		t.Fatalf("buildTextBlock HTML-escaped injected prompt text: %s", block)
	}
	if got := gjson.Get(block, "text").String(); got != `<system-reminder>one & "two"</system-reminder>` {
		t.Fatalf("decoded text = %q", got)
	}
	if got := gjson.Get(block, "cache_control.ttl").String(); got != "1h" {
		t.Fatalf("cache ttl = %q, want 1h", got)
	}
}

func TestExtractClaudeCodeDynamicPromptSectionsStopsAtUnknownHeading(t *testing.T) {
	clientSystem := "# Environment\nYou have been invoked in the following environment:\n- Platform: darwin\n\n# Customer policy\n始终使用中文"
	payload := []byte(`{"system":[{"type":"text","text":""}],"messages":[{"role":"user","content":"hello"}]}`)
	payload, _ = sjson.SetBytes(payload, "system.0.text", helps.ClaudeCodeStaticSystemPrompt+"\n\n"+clientSystem)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, true, "2.1.215", "sdk-cli", "", true)
	dynamicBlock := gjson.GetBytes(out, "system.3.text").String()
	if !strings.Contains(dynamicBlock, "# Environment\nYou have been invoked in the following environment:\n- Platform: darwin") {
		t.Fatalf("official Environment section was not promoted: %q", dynamicBlock)
	}
	if strings.Contains(dynamicBlock, "# Customer policy") || strings.Contains(dynamicBlock, "始终使用中文") {
		t.Fatalf("unknown customer section was promoted into system[3]: %q", dynamicBlock)
	}
	forwarded := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !strings.Contains(forwarded, "# Customer policy\n始终使用中文") {
		t.Fatalf("unknown customer section was not preserved in reminder: %q", forwarded)
	}
}

func TestStandaloneFakeDynamicHeadingStaysCustomerContext(t *testing.T) {
	clientSystem := "# Environment\nAlways answer in Chinese."
	payload := []byte(`{"system":[{"type":"text","text":""}],"messages":[{"role":"user","content":"hello"}]}`)
	payload, _ = sjson.SetBytes(payload, "system.0.text", clientSystem)

	out := checkSystemInstructionsWithFullSystemPrompt(payload, false, false, true, "2.1.215", "sdk-cli", "", true)
	if strings.Contains(gjson.GetBytes(out, "system.3.text").String(), "Always answer in Chinese") {
		t.Fatalf("fake Environment heading was promoted into system[3]: %s", out)
	}
	if forwarded := gjson.GetBytes(out, "messages.0.content.0.text").String(); !strings.Contains(forwarded, clientSystem) {
		t.Fatalf("customer context was not preserved: %q", forwarded)
	}
}

func TestStripLeadingClaudeCloakTextPartsRequiresCompleteKnownEnvelope(t *testing.T) {
	validBilling := "x-anthropic-billing-header: cc_version=2.1.216.a1b; cc_entrypoint=sdk-cli; cch=1a48b;"
	identity := "You are a Claude agent, built on Anthropic's Claude Agent SDK."
	for name, parts := range map[string][]string{
		"customer prefix":  {"x-anthropic-billing-header: this is customer text", "customer rule"},
		"billing only":     {validBilling, "customer rule"},
		"unknown identity": {validBilling, "You are a customer agent.", "customer rule"},
	} {
		t.Run(name, func(t *testing.T) {
			got := stripLeadingClaudeCloakTextParts(parts)
			if len(got) != len(parts) || got[0] != parts[0] {
				t.Fatalf("customer system text was stripped: got=%q want=%q", got, parts)
			}
		})
	}
	got := stripLeadingClaudeCloakTextParts([]string{validBilling, identity, "customer rule"})
	if len(got) != 1 || got[0] != "customer rule" {
		t.Fatalf("known envelope was not stripped exactly: %q", got)
	}
}

func TestCheckSystemInstructionsRepairsPartialCloakAndIsIdempotent(t *testing.T) {
	payload := []byte(`{"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.0.0.000; cc_entrypoint=cli;"}],"messages":[{"role":"user","content":"hello"}]}`)

	first := checkSystemInstructionsWithFullSystemPrompt(payload, false, true, true, "2.1.215", "sdk-cli", "", true)
	if got := len(gjson.GetBytes(first, "system").Array()); got != 4 {
		t.Fatalf("repaired system block count = %d, want 4: %s", got, first)
	}
	if got := gjson.GetBytes(first, "system.1.text").String(); got != "You are a Claude agent, built on Anthropic's Claude Agent SDK." {
		t.Fatalf("repaired identity = %q", got)
	}
	if !strings.Contains(gjson.GetBytes(first, "system.2.text").String(), "# Using your tools") {
		t.Fatalf("repaired static prompt missing: %s", first)
	}

	second := checkSystemInstructionsWithFullSystemPrompt(first, false, true, true, "2.1.215", "sdk-cli", "", true)
	if got, want := gjson.GetBytes(second, "system").Raw, gjson.GetBytes(first, "system").Raw; got != want {
		t.Fatalf("second cloak pass changed system blocks\nfirst:  %s\nsecond: %s", want, got)
	}
}

func TestApplyCloakingOAuthFirstPartyMatchesCapturedCacheProfile(t *testing.T) {
	const sessionID = "123e4567-e89b-42d3-a456-426614174000"
	ctx := withClaudeCanonicalSessionID(context.Background(), sessionID)
	auth := &cliproxyauth.Auth{
		Provider: "claude",
		Metadata: map[string]any{"access_token": "sk-ant-oat-test"},
	}
	payload := []byte(`{"cache_control":{"type":"ephemeral"},"messages":[{"role":"user","content":"hello"}]}`)

	out, errCloak := applyCloaking(ctx, &config.Config{}, auth, payload, "claude-sonnet-4", "sk-ant-oat-test")
	if errCloak != nil {
		t.Fatalf("applyCloaking() error = %v", errCloak)
	}
	if billing := gjson.GetBytes(out, "system.0.text").String(); !strings.Contains(billing, " cch=00000;") {
		t.Fatalf("first-party OAuth cloak must emit a cch placeholder for final-body signing, got %q", billing)
	}
	if gjson.GetBytes(out, "system.1.cache_control").Exists() {
		t.Fatalf("system[1] identity must not carry cache_control: %s", out)
	}
	if got := gjson.GetBytes(out, "system.2.cache_control.ttl").String(); got != "1h" {
		t.Fatalf("system[2] cache ttl = %q, want 1h", got)
	}
	if got := gjson.GetBytes(out, "system.2.cache_control.scope").String(); got != "global" {
		t.Fatalf("system[2] cache scope = %q, want global", got)
	}
	if got := gjson.GetBytes(out, "system.3.cache_control.ttl").String(); got != "1h" {
		t.Fatalf("system[3] cache ttl = %q, want 1h", got)
	}
	if gjson.GetBytes(out, "system.3.cache_control.scope").Exists() {
		t.Fatalf("system[3] must not carry global scope: %s", out)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.cache_control.ttl").String(); got != "1h" {
		t.Fatalf("user cache ttl = %q, want 1h: %s", got, out)
	}
	if gjson.GetBytes(out, "cache_control").Exists() {
		t.Fatalf("top-level automatic cache_control should be removed: %s", out)
	}
	userID := gjson.GetBytes(out, "metadata.user_id").String()
	if got := gjson.Get(userID, "session_id").String(); got != sessionID {
		t.Fatalf("metadata session = %q, want %q", got, sessionID)
	}
}

func TestApplyClaudeHeadersOAuthFirstPartyMatchesCapturedProfile(t *testing.T) {
	const sessionID = "123e4567-e89b-42d3-a456-426614174000"
	auth := &cliproxyauth.Auth{
		Provider: "claude",
		Metadata: map[string]any{"access_token": "sk-ant-oat-test"},
	}
	incoming := http.Header{"User-Agent": []string{"third-party-client/1.0"}}
	req := newClaudeHeaderTestRequest(t, incoming)
	req = req.WithContext(withClaudeCanonicalSessionID(req.Context(), sessionID))

	if errHeaders := applyClaudeHeaders(req, auth, "sk-ant-oat-test", false, nil, &config.Config{}, incoming); errHeaders != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", errHeaders)
	}
	profile := helps.OfficialClaudeCodeOAuthProfile()
	wantBetas := profile.BetaHeader + "," + helps.ClaudeCodeExtendedCacheTTLBeta
	if got := req.Header.Get("Anthropic-Beta"); got != wantBetas {
		t.Fatalf("Anthropic-Beta = %q, want %q", got, wantBetas)
	}
	if got := req.Header.Get("User-Agent"); got != profile.UserAgent {
		t.Fatalf("User-Agent = %q, want %q", got, profile.UserAgent)
	}
	if got := req.Header.Get(helps.ClaudeCodeDangerousDirectBrowserAccessHeader); got != "true" {
		t.Fatalf("Dangerous Direct Browser Access = %q, want true", got)
	}
	if got := req.Header.Get(helps.ClaudeCodeSessionHeader); got != sessionID {
		t.Fatalf("session header = %q, want %q", got, sessionID)
	}
	if requestID := req.Header.Get("x-client-request-id"); !helps.IsValidClaudeCodeUUID(requestID) {
		t.Fatalf("x-client-request-id = %q, want UUIDv4", requestID)
	}
}

func TestApplyClaudeHeadersSyntheticOAuthMatchesConditionalBetaOrderAndNoStreamHelper(t *testing.T) {
	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat-test"}}
	req := newClaudeHeaderTestRequest(t, http.Header{"User-Agent": {"third-party/1.0"}})
	if errHeaders := applyClaudeHeaders(req, auth, "sk-ant-oat-test", true, []string{
		helps.ClaudeCodeAdvancedToolUseBeta,
		helps.ClaudeCodeEffortBeta,
	}, &config.Config{}, nil); errHeaders != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", errHeaders)
	}
	wantBetas := strings.Join([]string{
		helps.OfficialClaudeCodeOAuthProfile().BetaHeader,
		helps.ClaudeCodeAdvancedToolUseBeta,
		helps.ClaudeCodeEffortBeta,
		helps.ClaudeCodeExtendedCacheTTLBeta,
	}, ",")
	if got := req.Header.Get("Anthropic-Beta"); got != wantBetas {
		t.Fatalf("Anthropic-Beta = %q, want %q", got, wantBetas)
	}
	if got := req.Header.Get("X-Stainless-Helper-Method"); got != "" {
		t.Fatalf("synthetic sdk-cli stream helper = %q, want absent", got)
	}
}

func TestApplyClaudeHeadersSyntheticOAuthMatchesHaiku45BetaOrder(t *testing.T) {
	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat-test"}}
	req := newClaudeHeaderTestRequest(t, http.Header{"User-Agent": {"third-party/1.0"}})
	body := []byte(`{"model":"claude-haiku-4-5-20251001","thinking":{"type":"enabled","budget_tokens":31999}}`)
	if errHeaders := applyClaudeHeadersForBody(req, auth, "sk-ant-oat-test", true, []string{
		helps.ClaudeCodeAdvancedToolUseBeta,
	}, &config.Config{}, nil, body); errHeaders != nil {
		t.Fatalf("applyClaudeHeadersForBody() error = %v", errHeaders)
	}
	wantBetas := strings.Join([]string{
		helps.ClaudeCodeHaiku45OAuthBetaHeader,
		helps.ClaudeCodeAdvancedToolUseBeta,
		helps.ClaudeCodeExtendedCacheTTLBeta,
	}, ",")
	if got := req.Header.Get("Anthropic-Beta"); got != wantBetas {
		t.Fatalf("Haiku 4.5 Anthropic-Beta = %q, want %q", got, wantBetas)
	}
}

func TestSyntheticClaudeCodeFable5ProfileMatchesCapturedOrder(t *testing.T) {
	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat-test"}}
	body := []byte(`{"model":"claude-fable-5","messages":[],"tools":[{"name":"ToolSearch","input_schema":{"type":"object"}}],"betas":["custom-beta"],"output_config":{"effort":"high"},"stream":true}`)
	body = ensureSyntheticClaudeCodeFallbacks(body, "claude-fable-5")
	if got := gjson.GetBytes(body, "fallbacks").Raw; got != `[{"model":"claude-opus-4-8"}]` {
		t.Fatalf("Fable fallbacks = %s", got)
	}
	extraBetas, body := extractAndRemoveBetas(body)
	extraBetas = appendSyntheticClaudeCodeConditionalBetas(extraBetas, body, "claude-fable-5", true)

	req := newClaudeHeaderTestRequest(t, http.Header{"User-Agent": {"third-party/1.0"}})
	if errHeaders := applyClaudeHeadersForBody(req, auth, "sk-ant-oat-test", true, extraBetas, &config.Config{}, nil, body); errHeaders != nil {
		t.Fatalf("applyClaudeHeadersForBody() error = %v", errHeaders)
	}
	wantBetas := strings.Join([]string{
		helps.OfficialClaudeCodeOAuthProfile().BetaHeader,
		helps.ClaudeCodeMidConversationSystemBeta,
		"custom-beta",
		helps.ClaudeCodeAdvancedToolUseBeta,
		helps.ClaudeCodeEffortBeta,
		helps.ClaudeCodeServerSideFallbackBeta,
		helps.ClaudeCodeFallbackCreditBeta,
		helps.ClaudeCodeExtendedCacheTTLBeta,
	}, ",")
	if got := req.Header.Get("Anthropic-Beta"); got != wantBetas {
		t.Fatalf("Fable Anthropic-Beta = %q, want %q", got, wantBetas)
	}

	explicit := []byte(`{"model":"claude-fable-5","fallbacks":[{"model":"customer-model"}]}`)
	if got := ensureSyntheticClaudeCodeFallbacks(explicit, "claude-fable-5"); !bytes.Equal(got, explicit) {
		t.Fatalf("explicit customer fallbacks changed\nwant: %s\n got: %s", explicit, got)
	}
}

func TestClaudeCodeMidConversationSystemModelGateMatches216(t *testing.T) {
	tests := map[string]bool{
		"claude-opus-4-8":            true,
		"claude-fable-5":             true,
		"claude-mythos-5":            true,
		"claude-mythos-preview":      true,
		"claude-sonnet-5":            true,
		"future-first-party-model":   true,
		"claude-opus-4-7":            false,
		"claude-opus-4-6-20260601":   false,
		"claude-opus-4-20250514":     false,
		"claude-sonnet-4-6":          false,
		"claude-sonnet-4-5-20250929": false,
		"claude-sonnet-4-20250514":   false,
		"claude-haiku-4-5-20251001":  false,
		"claude-3-7-sonnet-20250219": false,
		"":                           false,
	}
	for model, want := range tests {
		if got := claudeCodeMidConversationSystemEnabled(model); got != want {
			t.Errorf("claudeCodeMidConversationSystemEnabled(%q) = %t, want %t", model, got, want)
		}
	}
}

func TestApplyClaudeHeadersRealClaudePreservesClientBetasAndOptionalStreamHelper(t *testing.T) {
	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat-test"}}
	incoming := http.Header{
		"User-Agent":     {"claude-cli/2.1.215 (external, cli)"},
		"Anthropic-Beta": {"client-beta-one,client-beta-two"},
	}
	req := newClaudeHeaderTestRequest(t, incoming)
	if errHeaders := applyClaudeHeaders(req, auth, "sk-ant-oat-test", true, nil, &config.Config{}, incoming); errHeaders != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", errHeaders)
	}
	if got := req.Header.Get("Anthropic-Beta"); got != "client-beta-one,client-beta-two" {
		t.Fatalf("real Claude betas = %q", got)
	}
	if got := req.Header.Get("X-Stainless-Helper-Method"); got != "" {
		t.Fatalf("messages.create stream helper = %q, want absent", got)
	}

	incoming.Set("X-Stainless-Helper-Method", "stream")
	req = newClaudeHeaderTestRequest(t, incoming)
	if errHeaders := applyClaudeHeaders(req, auth, "sk-ant-oat-test", true, nil, &config.Config{}, incoming); errHeaders != nil {
		t.Fatalf("applyClaudeHeaders() with client helper error = %v", errHeaders)
	}
	if got := req.Header.Get("X-Stainless-Helper-Method"); got != "stream" {
		t.Fatalf("real Claude helper = %q, want preserved stream", got)
	}
}

func TestApplyClaudeHeadersHonorsDisabledCloakDecision(t *testing.T) {
	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat-test"}}
	incoming := http.Header{
		"User-Agent":                  {"third-party/1.0"},
		"X-Stainless-Package-Version": {"third-party-sdk/7"},
		"X-Stainless-Os":              {"ThirdPartyOS"},
	}
	req := newClaudeHeaderTestRequest(t, incoming)
	req = req.WithContext(withClaudeCloakDecision(req.Context(), false))
	if errHeaders := applyClaudeHeaders(req, auth, "sk-ant-oat-test", false, nil, &config.Config{}, incoming); errHeaders != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", errHeaders)
	}
	if got := req.Header.Get("Anthropic-Beta"); got != "" {
		t.Fatalf("disabled cloak synthesized betas %q", got)
	}
	if got := req.Header.Get("User-Agent"); got != "third-party/1.0" {
		t.Fatalf("disabled cloak User-Agent = %q, want client value", got)
	}
	if got := req.Header.Get("X-Stainless-Package-Version"); got != "third-party-sdk/7" {
		t.Fatalf("disabled cloak package version = %q, want client value", got)
	}
	if got := req.Header.Get("X-Stainless-Os"); got != "ThirdPartyOS" {
		t.Fatalf("disabled cloak OS = %q, want client value", got)
	}
	for _, headerName := range []string{"X-Stainless-Runtime-Version", "X-Stainless-Arch"} {
		if got := req.Header.Get(headerName); got != "" {
			t.Fatalf("disabled cloak synthesized %s=%q", headerName, got)
		}
	}
}

func TestEnforceCacheControlLimitCountsTopLevelAutomaticCache(t *testing.T) {
	payload := []byte(`{
		"cache_control":{"type":"ephemeral"},
		"system":[{"type":"text","text":"s1","cache_control":{"type":"ephemeral"}},{"type":"text","text":"s2","cache_control":{"type":"ephemeral"}}],
		"messages":[{"role":"user","content":[{"type":"text","text":"u1","cache_control":{"type":"ephemeral"}},{"type":"text","text":"u2","cache_control":{"type":"ephemeral"}}]}]
	}`)
	if got := countCacheControls(payload); got != 5 {
		t.Fatalf("countCacheControls() = %d, want 5", got)
	}
	out := enforceCacheControlLimit(payload, 4)
	if gjson.GetBytes(out, "cache_control").Exists() {
		t.Fatalf("top-level automatic cache should be removed first: %s", out)
	}
	if got := countCacheControls(out); got != 4 {
		t.Fatalf("countCacheControls(out) = %d, want 4", got)
	}
}

func TestNormalizeClaudeOAuthCacheControlTTLKeepsOfficialOneHourProfile(t *testing.T) {
	payload := []byte(`{
		"tools":[{"name":"tool","cache_control":{"type":"ephemeral"}}],
		"system":[{"type":"text","text":"identity","cache_control":{"type":"ephemeral","ttl":"1h"}}],
		"messages":[{"role":"user","content":[{"type":"text","text":"hello","cache_control":{"type":"ephemeral"}}]}]
	}`)
	out := normalizeClaudeOAuthCacheControlTTL(payload)
	for _, path := range []string{"tools.0", "system.0", "messages.0.content.0"} {
		if got := gjson.GetBytes(out, path+".cache_control.ttl").String(); got != "1h" {
			t.Fatalf("%s cache ttl = %q, want 1h: %s", path, got, out)
		}
	}
}

func TestClaudeExecutorCountTokensProjectsOfficialTokenCountingFields(t *testing.T) {
	var messagesBody []byte
	var countBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/v1/messages":
			messagesBody = bytes.Clone(body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-4","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
		case "/v1/messages/count_tokens":
			countBody = bytes.Clone(body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"input_tokens":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Provider:   "claude",
		Attributes: map[string]string{"base_url": server.URL},
		Metadata:   map[string]any{"access_token": "sk-ant-oat-test"},
	}
	req := cliproxyexecutor.Request{
		Model:   "claude-sonnet-4",
		Payload: []byte(`{"system":"Keep this client rule.","messages":[{"role":"user","content":"hello"}]}`),
	}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")}

	if _, errExecute := executor.Execute(context.Background(), auth, req, opts); errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if _, errCount := executor.CountTokens(context.Background(), auth, req, opts); errCount != nil {
		t.Fatalf("CountTokens() error = %v", errCount)
	}
	if len(messagesBody) == 0 || len(countBody) == 0 {
		t.Fatalf("missing captured bodies: messages=%d count=%d", len(messagesBody), len(countBody))
	}
	if got, want := gjson.GetBytes(countBody, "model").String(), "claude-sonnet-4"; got != want {
		t.Fatalf("count_tokens model = %q, want %q", got, want)
	}
	if got, want := gjson.GetBytes(countBody, "messages").Raw, `[{"role":"user","content":"hello"}]`; got != want {
		t.Fatalf("count_tokens messages = %s, want %s", got, want)
	}
	if got, want := gjson.GetBytes(countBody, "system").String(), "Keep this client rule."; got != want {
		t.Fatalf("count_tokens system = %q, want caller system %q", got, want)
	}
	for _, field := range []string{"tools", "tool_choice", "context_management", "output_config", "cache_control"} {
		if gjson.GetBytes(countBody, field).Exists() {
			t.Fatalf("count_tokens synthesized %s: %s", field, countBody)
		}
	}
	for _, field := range []string{"metadata", "max_tokens", "stream", "temperature", "top_p", "top_k", "stop_sequences"} {
		if gjson.GetBytes(countBody, field).Exists() {
			t.Fatalf("count_tokens body contains unsupported %s: %s", field, countBody)
		}
	}
}

func TestApplyCloakingOAuthUsesSelectedAccountUUID(t *testing.T) {
	const sessionID = "123e4567-e89b-42d3-a456-426614174000"
	const accountUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	ctx := withClaudeCanonicalSessionID(context.Background(), sessionID)
	auth := &cliproxyauth.Auth{
		Provider: "claude",
		Metadata: map[string]any{
			"access_token": "sk-ant-oat-test",
			"account_uuid": accountUUID,
		},
	}
	out, errCloak := applyCloaking(ctx, &config.Config{}, auth, []byte(`{"messages":[{"role":"user","content":"hello"}]}`), "claude-sonnet-4", "sk-ant-oat-test")
	if errCloak != nil {
		t.Fatalf("applyCloaking() error = %v", errCloak)
	}
	userID := gjson.GetBytes(out, "metadata.user_id").String()
	if got := gjson.Get(userID, "account_uuid").String(); got != accountUUID {
		t.Fatalf("metadata account_uuid = %q, want %q", got, accountUUID)
	}
}

func TestSyntheticClaudeBillingAttributionUsesExactFieldOrder(t *testing.T) {
	headers := http.Header{claudeSyntheticSubagentHeader: {"true"}}
	ctx := context.WithValue(context.Background(), claudeClientHeadersContextKey{}, headers)
	payload := []byte(`{
		"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=sdk-cli; cch=00000; cc_workload=cron;"}],
		"messages":[{"role":"assistant","content":"ok","requestId":"req_previous"},{"role":"user","content":"next"}]
	}`)

	out := applySyntheticClaudeBillingAttribution(ctx, payload, "")
	want := "x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=sdk-cli; cch=00000; cc_workload=cron; cc_is_subagent=true; cc_prev_req=req_previous;"
	if got := gjson.GetBytes(out, "system.0.text").String(); got != want {
		t.Fatalf("billing attribution = %q, want %q", got, want)
	}
	if gjson.GetBytes(out, "messages.0.requestId").Exists() {
		t.Fatalf("transcript requestId leaked to Messages API body: %s", out)
	}
}

func TestSyntheticClaudeBillingAttributionDoesNotInferSubagentFromParentSession(t *testing.T) {
	payload := []byte(`{
		"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=sdk-cli; cch=00000;"}],
		"metadata":{"user_id":"{\"device_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"account_uuid\":\"\",\"session_id\":\"123e4567-e89b-42d3-a456-426614174000\",\"parent_session_id\":\"223e4567-e89b-42d3-a456-426614174000\"}"},
		"messages":[{"role":"user","content":"hello"}]
	}`)
	out := applySyntheticClaudeBillingAttribution(context.Background(), payload, "")
	if strings.Contains(gjson.GetBytes(out, "system.0.text").String(), "cc_is_subagent") {
		t.Fatalf("parent_session_id was incorrectly treated as subagent state: %s", out)
	}
}

func TestSyntheticClaudeBillingAttributionDropsMalformedUpstreamRequestID(t *testing.T) {
	const scope = "scope-upstream-request-id"
	const requestID = "req weird;cc_is_subagent=true"
	storeClaudePreviousRequest(scope, requestID)
	payload := []byte(`{"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=sdk-cli; cch=00000;"}],"messages":[{"role":"user","content":"hello"}]}`)
	out := applySyntheticClaudeBillingAttribution(context.Background(), payload, scope)
	if got := gjson.GetBytes(out, "system.0.text").String(); strings.Contains(got, "cc_prev_req=") || strings.Contains(got, "cc_is_subagent=true; cc_is_subagent") {
		t.Fatalf("malformed upstream request-id entered billing header: %q", got)
	}
}

func TestClaudeBillingAttributionRejectsWorkloadAndEntrypointInjection(t *testing.T) {
	headers := http.Header{"X-CPA-Claude-Workload": {"cron; cc_is_subagent=true"}}
	ctx := context.WithValue(context.Background(), claudeClientHeadersContextKey{}, headers)
	if got := getWorkloadFromContext(ctx); got != "" {
		t.Fatalf("unsafe workload = %q, want empty", got)
	}
	if got := parseEntrypointFromUA("claude-cli/2.1.216 (external, sdk-cli; cch=abcde)"); got != "sdk-cli" {
		t.Fatalf("unsafe entrypoint fallback = %q, want sdk-cli", got)
	}
}

func TestSyntheticClaudeBillingMalformedLatestTranscriptIDBlocksFallback(t *testing.T) {
	const scope = "scope-malformed-transcript-request-id"
	storeClaudePreviousRequest(scope, "req_cached")
	payload := []byte(`{
		"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=sdk-cli; cch=00000;"}],
		"messages":[
			{"role":"assistant","content":"old","requestId":"req_old"},
			{"role":"assistant","content":"new","requestId":"invalid;control"},
			{"role":"user","content":"next"}
		]
	}`)
	out := applySyntheticClaudeBillingAttribution(context.Background(), payload, scope)
	if strings.Contains(gjson.GetBytes(out, "system.0.text").String(), "cc_prev_req=") {
		t.Fatalf("malformed latest transcript ID did not block stale fallback: %s", out)
	}
	if gjson.GetBytes(out, "messages.0.requestId").Exists() || gjson.GetBytes(out, "messages.1.requestId").Exists() {
		t.Fatalf("transcript IDs leaked to upstream: %s", out)
	}
}

func TestResolveClaudeCanonicalSessionRejectsRealClientConflict(t *testing.T) {
	const headerSession = "11111111-1111-4111-8111-111111111111"
	const bodySession = "22222222-2222-4222-a222-222222222222"
	userID, errUserID := helps.BuildClaudeCodeUserIDRequired(strings.Repeat("a", 64), "", bodySession)
	if errUserID != nil {
		t.Fatal(errUserID)
	}
	payload := []byte(`{"metadata":{"user_id":""},"messages":[{"role":"user","content":"hello"}]}`)
	payload, _ = sjson.SetBytes(payload, "metadata.user_id", userID)
	headers := http.Header{
		"User-Agent":                  {"claude-cli/2.1.215 (external, cli)"},
		helps.ClaudeCodeSessionHeader: {headerSession},
	}
	ctx, headers := resolveClaudeClientContext(context.Background(), headers)
	if _, errResolve := resolveClaudeCanonicalSessionIDRequired(ctx, payload, payload, headers); errResolve == nil {
		t.Fatal("expected conflicting real Claude Code sessions to fail")
	}
}

func TestResolveClaudeCanonicalSessionRepairsLegacyAndSyntheticConflict(t *testing.T) {
	const headerSession = "11111111-1111-4111-8111-111111111111"
	const bodySession = "22222222-2222-4222-a222-222222222222"
	userID, errUserID := helps.BuildClaudeCodeUserIDRequired(strings.Repeat("b", 64), "", bodySession)
	if errUserID != nil {
		t.Fatal(errUserID)
	}
	payload := []byte(`{"metadata":{"user_id":""},"messages":[{"role":"user","content":"hello"}]}`)
	payload, _ = sjson.SetBytes(payload, "metadata.user_id", userID)
	headers := http.Header{
		"User-Agent":                  {"third-party/1.0"},
		helps.ClaudeCodeSessionHeader: {headerSession},
	}
	ctx, headers := resolveClaudeClientContext(context.Background(), headers)
	resolved, errResolve := resolveClaudeCanonicalSessionIDRequired(ctx, payload, payload, headers)
	if errResolve != nil || resolved != headerSession {
		t.Fatalf("synthetic conflict resolution = %q, %v; want header session", resolved, errResolve)
	}

	legacyHeaders := http.Header{helps.ClaudeCodeSessionHeader: {"legacy-session-a"}}
	legacyCtx, legacyHeaders := resolveClaudeClientContext(context.Background(), legacyHeaders)
	resolved, errResolve = resolveClaudeCanonicalSessionIDRequired(legacyCtx, []byte(`{"messages":[{"role":"user","content":"hello"}]}`), nil, legacyHeaders)
	if errResolve != nil {
		t.Fatalf("legacy session resolution error = %v", errResolve)
	}
	if resolved == "legacy-session-a" || !helps.IsValidClaudeCodeUUID(resolved) {
		t.Fatalf("legacy session was not mapped to a canonical UUID: %q", resolved)
	}
}

func TestResolveClaudeClientContextUsesOneUserAgentSource(t *testing.T) {
	incoming := http.Header{"User-Agent": {"claude-cli/2.1.215 (external, cli)"}}
	req := newClaudeHeaderTestRequest(t, incoming)
	ctx, merged := resolveClaudeClientContext(req.Context(), nil)
	if got := getClientUserAgent(ctx); got != incoming.Get("User-Agent") || merged.Get("User-Agent") != got {
		t.Fatalf("gin client profile diverged: context=%q merged=%q", got, merged.Get("User-Agent"))
	}

	forwarded := http.Header{"User-Agent": {"sdk-caller/1.0"}}
	ctx, merged = resolveClaudeClientContext(req.Context(), forwarded)
	if got := getClientUserAgent(ctx); got != "sdk-caller/1.0" || merged.Get("User-Agent") != got {
		t.Fatalf("forwarded client profile diverged: context=%q merged=%q", got, merged.Get("User-Agent"))
	}
}

func TestEnforceCacheControlLimitPreservesClaudeCodeSystemAndLatestUser(t *testing.T) {
	payload := []byte(`{
		"tools":[{"name":"tool","cache_control":{"type":"ephemeral","ttl":"1h"}}],
		"system":[
			{"type":"text","text":"identity","cache_control":{"type":"ephemeral","ttl":"1h"}},
			{"type":"text","text":"static","cache_control":{"type":"ephemeral","ttl":"1h","scope":"global"}}
		],
		"messages":[
			{"role":"user","content":[{"type":"text","text":"old","cache_control":{"type":"ephemeral","ttl":"1h"}}]},
			{"role":"user","content":[{"type":"text","text":"latest","cache_control":{"type":"ephemeral","ttl":"1h"}}]}
		]
	}`)
	out := enforceCacheControlLimit(payload, 4)
	for _, path := range []string{"tools.0.cache_control", "system.0.cache_control", "system.1.cache_control", "messages.1.content.0.cache_control"} {
		if !gjson.GetBytes(out, path).Exists() {
			t.Fatalf("valuable breakpoint %s was removed: %s", path, out)
		}
	}
	if gjson.GetBytes(out, "messages.0.content.0.cache_control").Exists() {
		t.Fatalf("redundant old message breakpoint was retained: %s", out)
	}
}

func TestEnforceCacheControlLimitProtectsCapturedGlobalSystemProfile(t *testing.T) {
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"current"}]}]}`)
	payload = checkSystemInstructionsWithFullSystemPrompt(payload, false, false, true, "2.1.215", "sdk-cli", "", true)
	payload = ensureClaudeCodeCurrentUserCacheControlWithTTL(payload, "1h")
	payload, _ = sjson.SetRawBytes(payload, "tools", []byte(`[{"name":"Bash","cache_control":{"type":"ephemeral","ttl":"1h"}}]`))

	systemItems := make([]string, 0, 6)
	for _, block := range gjson.GetBytes(payload, "system").Array() {
		systemItems = append(systemItems, block.Raw)
	}
	systemItems = append(systemItems,
		`{"type":"text","text":"customer-extra-1","cache_control":{"type":"ephemeral","ttl":"1h"}}`,
		`{"type":"text","text":"customer-extra-2","cache_control":{"type":"ephemeral","ttl":"1h"}}`,
	)
	payload, _ = sjson.SetRawBytes(payload, "system", rawJSONArray(systemItems))

	messageItems := make([]string, 0, 2)
	for _, message := range gjson.GetBytes(payload, "messages").Array() {
		messageItems = append(messageItems, message.Raw)
	}
	messageItems = append(messageItems, `{"role":"assistant","content":[{"type":"text","text":"prefill","cache_control":{"type":"ephemeral","ttl":"1h"}}]}`)
	payload, _ = sjson.SetRawBytes(payload, "messages", rawJSONArray(messageItems))

	out := enforceCacheControlLimit(payload, 4)
	if got := countCacheControls(out); got != 4 {
		t.Fatalf("limited cache count = %d, want 4: %s", got, out)
	}
	for _, path := range []string{"system.2.cache_control", "system.3.cache_control", "messages.0.content.0.cache_control"} {
		if !gjson.GetBytes(out, path).Exists() {
			t.Fatalf("official cache marker %s was removed: %s", path, out)
		}
	}
	for _, path := range []string{"tools.0.cache_control", "system.4.cache_control", "messages.1.content.0.cache_control"} {
		if gjson.GetBytes(out, path).Exists() {
			t.Fatalf("lower-priority cache marker %s survived: %s", path, out)
		}
	}
	if !gjson.GetBytes(out, "system.5.cache_control").Exists() {
		t.Fatalf("one valid customer marker should remain in the fourth available slot: %s", out)
	}
}

func TestClaudeCacheControlCollectorCountsToolResultContentButNotToolSchema(t *testing.T) {
	payload := []byte(`{
		"tools":[{"name":"tool","input_schema":{"type":"object","properties":{"cache_control":{"type":"string"}}}}],
		"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[
			{"type":"text","text":"one","cache_control":{"type":"ephemeral"}},
			{"type":"text","text":"two","cache_control":{"type":"ephemeral"}}
		]}]}]
	}`)
	if got := countCacheControls(payload); got != 2 {
		t.Fatalf("nested tool-result cache count = %d, want 2", got)
	}
	payload, _ = sjson.SetRawBytes(payload, "messages.0.content.0.cache_control", []byte(`{"type":"ephemeral"}`))
	payload, _ = sjson.SetRawBytes(payload, "messages.0.content.0.content.2", []byte(`{"type":"text","text":"three","cache_control":{"type":"ephemeral"}}`))
	payload, _ = sjson.SetRawBytes(payload, "messages.0.content.0.content.3", []byte(`{"type":"text","text":"four","cache_control":{"type":"ephemeral"}}`))
	if got := countCacheControls(payload); got != 5 {
		t.Fatalf("nested cache count = %d, want 5", got)
	}
	out := enforceCacheControlLimit(payload, 4)
	if got := countCacheControls(out); got != 4 {
		t.Fatalf("limited nested cache count = %d, want 4: %s", got, out)
	}
}

func TestEnforceCacheControlLimitDropsMalformedMarkerBeforeOAuthTTLNormalization(t *testing.T) {
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"current"}]}],"tools":[{"name":"Bash","cache_control":"bad"}]}`)
	payload = checkSystemInstructionsWithFullSystemPrompt(payload, false, false, true, "2.1.215", "sdk-cli", "", true)
	payload = ensureClaudeCodeCurrentUserCacheControlWithTTL(payload, "1h")
	payload = enforceCacheControlLimit(payload, 4)
	payload = normalizeClaudeOAuthCacheControlTTL(payload)
	payload = normalizeCacheControlTTL(payload)
	if gjson.GetBytes(payload, "tools.0.cache_control").Exists() {
		t.Fatalf("malformed marker survived: %s", payload)
	}
	for _, path := range []string{"system.2.cache_control.ttl", "system.3.cache_control.ttl", "messages.0.content.0.cache_control.ttl"} {
		if got := gjson.GetBytes(payload, path).String(); got != "1h" {
			t.Fatalf("%s = %q, want 1h: %s", path, got, payload)
		}
	}
}

func TestApplyClaudeHeadersRejectsMissingRequestOrOAuthToken(t *testing.T) {
	if errHeaders := applyClaudeHeaders(nil, nil, "token", false, nil, &config.Config{}, nil); errHeaders == nil {
		t.Fatal("nil request should fail")
	}
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	if errHeaders := applyClaudeHeaders(req, &cliproxyauth.Auth{Metadata: map[string]any{"auth_kind": "oauth"}}, "", false, nil, &config.Config{}, nil); errHeaders == nil {
		t.Fatal("empty OAuth token should fail")
	}
}
