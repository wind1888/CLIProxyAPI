package executor

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	xxHash64 "github.com/pierrec/xxHash/xxHash64"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// claudeCCHSeed is the seed used by Claude Code's native request-body signer.
// It is verified against official 2.1.177, 2.1.207, 2.1.210, 2.1.211,
// 2.1.212, and 2.1.215 requests and the 2.1.215 darwin-arm64 binary.
const claudeCCHSeed uint64 = 0x4D659218E32A3268

var claudeCCHSeedsByVersion = map[string]uint64{
	"2.1.177": claudeCCHSeed,
	"2.1.207": claudeCCHSeed,
	"2.1.210": claudeCCHSeed,
	"2.1.211": claudeCCHSeed,
	"2.1.212": claudeCCHSeed,
	"2.1.215": claudeCCHSeed,
}

// Anchor cch to the generated billing header so a user message that quotes a
// cch token is never used as the placeholder or rewritten.
var claudeBillingHeaderCCHPattern = regexp.MustCompile(`(cc_entrypoint=[a-z0-9-]{1,32}; cch=)[0-9a-fA-F]{5}(;)`)
var claudeBillingHeaderVersionPattern = regexp.MustCompile(`\bcc_version=([0-9]+\.[0-9]+\.[0-9]+)\.[0-9a-fA-F]{3};`)

func claudeCCHSeedForVersion(version string) (uint64, bool) {
	seed, ok := claudeCCHSeedsByVersion[strings.TrimSpace(version)]
	return seed, ok
}

func claudeCCHSigningEnabled(cfg *config.Config, firstPartyOAuth bool, baseURL string) bool {
	if !isClaudeFirstPartyBaseURL(baseURL) {
		return false
	}
	version := helps.DefaultClaudeVersion(cfg)
	if firstPartyOAuth {
		version = helps.OfficialClaudeCodeOAuthProfile().Version
	}
	_, supported := claudeCCHSeedForVersion(version)
	return supported
}

func signAnthropicMessagesBody(body []byte) ([]byte, error) {
	billingBlock := gjson.GetBytes(body, "system.0.text")
	if billingBlock.Type != gjson.String {
		return body, fmt.Errorf("Claude cch billing block is missing or not text")
	}
	billingHeader := billingBlock.String()
	if !strings.HasPrefix(billingHeader, "x-anthropic-billing-header:") {
		return body, fmt.Errorf("Claude cch billing block has an invalid prefix")
	}
	versionMatch := claudeBillingHeaderVersionPattern.FindStringSubmatch(billingHeader)
	if len(versionMatch) != 2 {
		return body, fmt.Errorf("Claude cch billing block has an invalid version")
	}
	seed, supported := claudeCCHSeedForVersion(versionMatch[1])
	if !supported {
		return body, fmt.Errorf("Claude cch version %s is not calibrated", versionMatch[1])
	}
	if matches := claudeBillingHeaderCCHPattern.FindAllStringIndex(billingHeader, -1); len(matches) != 1 {
		return body, fmt.Errorf("Claude cch billing block contains %d signing placeholders", len(matches))
	}

	material, err := buildClaudeCCHMaterial(body, billingHeader)
	if err != nil {
		return body, fmt.Errorf("build Claude cch projection: %w", err)
	}

	cch := fmt.Sprintf("%05x", xxHash64.Checksum(material, seed)&0xFFFFF)
	signedBillingHeader := claudeBillingHeaderCCHPattern.ReplaceAllString(billingHeader, "${1}"+cch+"${2}")
	signedBody, err := sjson.SetBytes(body, "system.0.text", signedBillingHeader)
	if err != nil {
		return body, fmt.Errorf("write Claude cch signature: %w", err)
	}
	return signedBody, nil
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
