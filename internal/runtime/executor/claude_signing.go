package executor

import (
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	xxHash64 "github.com/pierrec/xxHash/xxHash64"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// claudeCCHSeed is the seed used by Claude Code's native request-body signer.
// It is verified against official 2.1.215 and 2.1.216 requests and binaries.
const claudeCCHSeed uint64 = 0x4D659218E32A3268

var claudeCCHSeedsByVersion = map[string]uint64{
	"2.1.215": claudeCCHSeed,
	"2.1.216": claudeCCHSeed,
}

// Anchor cch to the generated billing header so a user message that quotes a
// cch token is never used as the placeholder or rewritten.
var claudeBillingHeaderCCHPattern = regexp.MustCompile(`(cc_entrypoint=[a-z0-9-]{1,32}; cch=)[0-9a-fA-F]{5}(;)`)
var claudeBillingHeaderVersionedCCHPattern = regexp.MustCompile(`x-anthropic-billing-header: cc_version=([0-9]+\.[0-9]+\.[0-9]+)\.[0-9a-fA-F]{3}; cc_entrypoint=[a-z0-9-]{1,32}; cch=([0-9a-fA-F]{5});`)

func claudeCCHSeedForVersion(version string) (uint64, bool) {
	seed, ok := claudeCCHSeedsByVersion[strings.TrimSpace(version)]
	return seed, ok
}

func claudeCCHSigningEnabled(_ *config.Config, firstPartyOAuth bool, baseURL string) bool {
	if !firstPartyOAuth || !isClaudeFirstPartyBaseURL(baseURL) {
		return false
	}
	version := helps.OfficialClaudeCodeOAuthProfile().Version
	_, supported := claudeCCHSeedForVersion(version)
	return supported
}

func signAnthropicMessagesBody(body []byte) ([]byte, error) {
	placeholderOffset, ok := findClaudeCCHPlaceholder(body)
	if !ok {
		// The native hook is intentionally silent when its exact trigger is
		// absent (including already-signed requests).
		return body, nil
	}
	material, err := buildClaudeCCHMaterial(body)
	if err != nil {
		return body, fmt.Errorf("build Claude cch projection: %w", err)
	}
	version := helps.OfficialClaudeCodeOAuthProfile().Version
	seed, supported := claudeCCHSeedForVersion(version)
	if !supported {
		return body, nil
	}
	cch := fmt.Sprintf("%05x", xxHash64.Checksum(material, seed)&0xFFFFF)
	signedBody := bytes.Clone(body)
	copy(signedBody[placeholderOffset:placeholderOffset+5], cch)
	return signedBody, nil
}

// resignAnthropicMessagesBody refreshes an existing first-party CCH after the
// proxy has applied an explicitly configured body transformation. The version
// is read from the billing block so unknown client versions remain untouched.
func resignAnthropicMessagesBody(body []byte) ([]byte, error) {
	cchOffset, version, ok := findClaudeVersionedCCH(body)
	if !ok {
		return body, nil
	}
	seed, supported := claudeCCHSeedForVersion(version)
	if !supported {
		return body, nil
	}
	zeroed := bytes.Clone(body)
	copy(zeroed[cchOffset:cchOffset+5], "00000")
	material, err := buildClaudeCCHMaterial(zeroed)
	if err != nil {
		return body, fmt.Errorf("build Claude cch projection: %w", err)
	}
	cch := fmt.Sprintf("%05x", xxHash64.Checksum(material, seed)&0xFFFFF)
	signedBody := bytes.Clone(body)
	copy(signedBody[cchOffset:cchOffset+5], cch)
	return signedBody, nil
}

func findClaudeVersionedCCH(body []byte) (int, string, bool) {
	systemOffset := bytes.Index(body, claudeCCHSystemPattern)
	if systemOffset < 0 {
		return 0, "", false
	}
	windowEnd := systemOffset + claudeCCHSystemSearchWindow
	if windowEnd > len(body) {
		windowEnd = len(body)
	}
	window := body[systemOffset:windowEnd]
	match := claudeBillingHeaderVersionedCCHPattern.FindSubmatchIndex(window)
	if len(match) != 6 {
		return 0, "", false
	}
	version := string(window[match[2]:match[3]])
	cchOffset := systemOffset + match[4]
	return cchOffset, version, true
}

func resolveClaudeKeyConfig(cfg *config.Config, auth *cliproxyauth.Auth) *config.ClaudeKey {
	if cfg == nil || auth == nil {
		return nil
	}

	apiKey, baseURL := claudeCreds(auth)
	if apiKey == "" {
		return nil
	}

	for i := range cfg.ClaudeKey {
		entry := &cfg.ClaudeKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if cfgKey != apiKey {
			continue
		}
		if baseURL != "" && cfgBase != "" && !claudeBaseURLsEqual(cfgBase, baseURL) {
			continue
		}
		return entry
	}

	return nil
}

func claudeBaseURLsEqual(left, right string) bool {
	leftURL, errLeft := url.Parse(strings.TrimSpace(left))
	rightURL, errRight := url.Parse(strings.TrimSpace(right))
	if errLeft != nil || errRight != nil {
		return strings.TrimSpace(left) == strings.TrimSpace(right)
	}
	return strings.EqualFold(leftURL.Scheme, rightURL.Scheme) &&
		strings.EqualFold(leftURL.Hostname(), rightURL.Hostname()) &&
		leftURL.Port() == rightURL.Port() &&
		leftURL.EscapedPath() == rightURL.EscapedPath() &&
		leftURL.RawQuery == rightURL.RawQuery
}

// resolveClaudeKeyCloakConfig finds the matching ClaudeKey config and returns its CloakConfig.
func resolveClaudeKeyCloakConfig(cfg *config.Config, auth *cliproxyauth.Auth) *config.CloakConfig {
	entry := resolveClaudeKeyConfig(cfg, auth)
	if entry == nil {
		return nil
	}
	return entry.Cloak
}

func rebuildMidSystemMessageEnabled(cfg *config.Config, auth *cliproxyauth.Auth) bool {
	if auth != nil && auth.Attributes != nil && strings.EqualFold(strings.TrimSpace(auth.Attributes["rebuild_mid_system_message"]), "true") {
		return true
	}
	entry := resolveClaudeKeyConfig(cfg, auth)
	return entry != nil && entry.RebuildMidSystemMessage
}
