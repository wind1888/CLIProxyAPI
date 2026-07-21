package executor

import (
	"bytes"
	"os"
	"strconv"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func claudeCCHFromBody(t *testing.T, body []byte) string {
	t.Helper()
	billingHeader := gjson.GetBytes(body, "system.0.text").String()
	match := claudeBillingHeaderCCHPattern.FindStringSubmatchIndex(billingHeader)
	if len(match) != 6 {
		t.Fatalf("billing header does not contain cch: %q", billingHeader)
	}
	return billingHeader[match[3]:match[4]]
}

func mustSignAnthropicMessagesBody(t *testing.T, body []byte) []byte {
	t.Helper()
	signed, errSign := signAnthropicMessagesBody(body)
	if errSign != nil {
		t.Fatalf("signAnthropicMessagesBody() error = %v", errSign)
	}
	return signed
}

func TestSignAnthropicMessagesBodyMatchesPublicClaudeCodeGolden(t *testing.T) {
	want, errRead := os.ReadFile("testdata/cch-cc2.1.215.json")
	if errRead != nil {
		t.Fatal(errRead)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))

	input := bytes.Replace(want, []byte("cch=c4060;"), []byte("cch=00000;"), 1)
	got := mustSignAnthropicMessagesBody(t, input)
	if !bytes.Equal(got, want) {
		t.Fatalf("signed body does not match official golden\nwant: %s\n got: %s", want, got)
	}
	if gotAgain := mustSignAnthropicMessagesBody(t, got); !bytes.Equal(gotAgain, got) {
		t.Fatalf("signing is not idempotent\nfirst:  %s\nsecond: %s", got, gotAgain)
	}
}

func TestSignAnthropicMessagesBodyMatchesOfficialClaudeCode216Golden(t *testing.T) {
	want, errRead := os.ReadFile("testdata/cch-cc2.1.216.json")
	if errRead != nil {
		t.Fatal(errRead)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))

	input := bytes.Replace(want, []byte("cch=cb011;"), []byte("cch=00000;"), 1)
	if bytes.Equal(input, want) {
		t.Fatal("official 2.1.216 golden does not contain the captured cch")
	}
	got := mustSignAnthropicMessagesBody(t, input)
	if !bytes.Equal(got, want) {
		t.Fatalf("signed body does not match official 2.1.216 golden\nwant: %s\n got: %s", want, got)
	}
	resigned, errResign := resignAnthropicMessagesBody(want)
	if errResign != nil {
		t.Fatalf("resignAnthropicMessagesBody() error = %v", errResign)
	}
	if !bytes.Equal(resigned, want) {
		t.Fatalf("official 2.1.216 golden failed independent re-sign verification\nwant: %s\n got: %s", want, resigned)
	}
}

func TestCurrentClaudeCodeVersionHasVerifiedNativeCCHSeed(t *testing.T) {
	version := helps.OfficialClaudeCodeOAuthProfile().Version
	seed, ok := claudeCCHSeedForVersion(version)
	if !ok || seed != claudeCCHSeed {
		t.Fatalf("CCH seed for current Claude Code %s = %#x, %t", version, seed, ok)
	}
	if version != "2.1.216" {
		t.Fatalf("test baseline version = %q, want 2.1.216", version)
	}
}

func TestSignAnthropicMessagesBodyMatchesOfficialRawByteVariants(t *testing.T) {
	signedBase, errRead := os.ReadFile("testdata/cch-cc2.1.215.json")
	if errRead != nil {
		t.Fatal(errRead)
	}
	signedBase = bytes.TrimSuffix(signedBase, []byte("\n"))
	base := bytes.Replace(signedBase, []byte("cch=c4060;"), []byte("cch=00000;"), 1)

	reorder := func(body []byte) []byte {
		keys := []string{"model", "system", "messages", "tools", "metadata", "max_tokens", "thinking", "context_management", "output_config", "stream"}
		result := make([]byte, 0, len(body))
		result = append(result, '{')
		for index, key := range keys {
			value := gjson.GetBytes(body, key)
			if !value.Exists() {
				t.Fatalf("official fixture missing %q", key)
			}
			if index > 0 {
				result = append(result, ',')
			}
			result = strconv.AppendQuote(result, key)
			result = append(result, ':')
			result = append(result, value.Raw...)
		}
		return append(result, '}')
	}

	tests := map[string]struct {
		mutate  func([]byte) []byte
		wantCCH string
	}{
		"control": {
			mutate:  bytes.Clone,
			wantCCH: "c4060",
		},
		"whitespace": {
			mutate: func(body []byte) []byte {
				return bytes.Replace(body, []byte(`"messages":`), []byte(`"messages" : `), 1)
			},
			wantCCH: "98096",
		},
		"escape spelling": {
			mutate: func(body []byte) []byte {
				return bytes.Replace(body, []byte("CCH_ESC_ALPHA"), []byte(`CCH_ESC_\u0041LPHA`), 1)
			},
			wantCCH: "52e65",
		},
		"duplicate key": {
			mutate: func(body []byte) []byte {
				return bytes.Replace(body, []byte(`,"stream":true}`), []byte(`,"stream":true,"stream":true}`), 1)
			},
			wantCCH: "ed17e",
		},
		"property order": {
			mutate:  reorder,
			wantCCH: "244c0",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := mustSignAnthropicMessagesBody(t, test.mutate(bytes.Clone(base)))
			if gotCCH := claudeCCHFromBody(t, got); gotCCH != test.wantCCH {
				t.Fatalf("cch = %q, want official 2.1.215 %q", gotCCH, test.wantCCH)
			}
		})
	}
}

func TestSignAnthropicMessagesBodyUsesOfficialProjection(t *testing.T) {
	signedBase, errRead := os.ReadFile("testdata/cch-cc2.1.215.json")
	if errRead != nil {
		t.Fatal(errRead)
	}
	signedBase = bytes.TrimSuffix(signedBase, []byte("\n"))
	base := bytes.Replace(signedBase, []byte("cch=c4060;"), []byte("cch=00000;"), 1)
	wantCCH := claudeCCHFromBody(t, mustSignAnthropicMessagesBody(t, base))

	variants := map[string]func([]byte) []byte{
		"model value": func(body []byte) []byte {
			body, _ = sjson.SetBytes(body, "model", "rewritten-model")
			return body
		},
		"max tokens": func(body []byte) []byte {
			body, _ = sjson.SetBytes(body, "max_tokens", 1)
			return body
		},
		"fallbacks": func(body []byte) []byte {
			body, _ = sjson.SetRawBytes(body, "fallbacks", []byte(`["fallback-model"]`))
			return body
		},
		"fallback credit token": func(body []byte) []byte {
			body, _ = sjson.SetBytes(body, "fallback_credit_token", "routing-token")
			return body
		},
	}
	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			got := claudeCCHFromBody(t, mustSignAnthropicMessagesBody(t, mutate(bytes.Clone(base))))
			if got != wantCCH {
				t.Fatalf("cch = %q, want projection-stable %q", got, wantCCH)
			}
		})
	}

	changed, _ := sjson.SetBytes(base, "messages.0.content.1.text", "semantic change")
	if got := claudeCCHFromBody(t, mustSignAnthropicMessagesBody(t, changed)); got == wantCCH {
		t.Fatalf("message change unexpectedly preserved cch %q", got)
	}
}

func TestSignAnthropicMessagesBodyOnlyRewritesBillingCCH(t *testing.T) {
	const quoted = "cc_entrypoint=sdk-cli; cch=dead1;"
	body := []byte(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"cc_entrypoint=sdk-cli; cch=dead1;"}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.215.abc; cc_entrypoint=sdk-cli; cch=00000;"}],"max_tokens":32000,"stream":true}`)

	signed := mustSignAnthropicMessagesBody(t, body)
	if got := gjson.GetBytes(signed, "messages.0.content").String(); got != quoted {
		t.Fatalf("quoted user cch changed: got %q, want %q", got, quoted)
	}
	if got := claudeCCHFromBody(t, signed); got == "00000" || len(got) != 5 {
		t.Fatalf("billing cch was not signed: %q", got)
	}

	for name, unmatched := range map[string][]byte{
		"missing billing": []byte(`{"model":"claude-sonnet-4","messages":[]}`),
		"malformed json":  append(bytes.Clone(signed), '{'),
	} {
		t.Run(name, func(t *testing.T) {
			got, errSign := signAnthropicMessagesBody(unmatched)
			if errSign != nil {
				t.Fatalf("signAnthropicMessagesBody() error = %v", errSign)
			}
			if !bytes.Equal(got, unmatched) {
				t.Fatalf("unmatched body changed\nwant: %s\n got: %s", unmatched, got)
			}
		})
	}
}

func TestResignAnthropicMessagesBodyRefreshesSupportedNativeCCH(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"before"}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.216.abc; cc_entrypoint=sdk-cli; cch=00000;"}],"max_tokens":32000,"stream":true}`)
	signed := mustSignAnthropicMessagesBody(t, body)
	oldCCH := claudeCCHFromBody(t, signed)
	mutated, _ := sjson.SetBytes(signed, "messages.0.content", "after")
	resigned, errResign := resignAnthropicMessagesBody(mutated)
	if errResign != nil {
		t.Fatalf("resignAnthropicMessagesBody() error = %v", errResign)
	}
	if got := claudeCCHFromBody(t, resigned); got == oldCCH || got == "00000" {
		t.Fatalf("resigned cch = %q, old = %q", got, oldCCH)
	}
	zeroed := bytes.Replace(resigned, []byte("cch="+claudeCCHFromBody(t, resigned)+";"), []byte("cch=00000;"), 1)
	want := mustSignAnthropicMessagesBody(t, zeroed)
	if !bytes.Equal(resigned, want) {
		t.Fatalf("resigned body differs from signing final bytes\nwant: %s\n got: %s", want, resigned)
	}
}

func TestResignAnthropicMessagesBodyLeavesUnknownClientVersionUntouched(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=9.9.9.abc; cc_entrypoint=sdk-cli; cch=abcde;"}],"max_tokens":32000}`)
	got, errResign := resignAnthropicMessagesBody(body)
	if errResign != nil {
		t.Fatalf("resignAnthropicMessagesBody() error = %v", errResign)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("unknown-version request changed\nwant: %s\n got: %s", body, got)
	}
}

func TestSignAnthropicMessagesBodyUsesNativeSeedIndependentOfBillingText(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4","messages":[],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=9.9.9.abc; cc_entrypoint=sdk-cli; cch=00000;"}],"max_tokens":32000}`)

	got, errSign := signAnthropicMessagesBody(body)
	if errSign != nil {
		t.Fatalf("signAnthropicMessagesBody() error = %v", errSign)
	}
	if bytes.Equal(got, body) || claudeCCHFromBody(t, got) == "00000" {
		t.Fatalf("native signer did not patch exact placeholder: %s", got)
	}
}

func TestClaudeCCHSigningEnabledUsesHostAndCalibratedVersion(t *testing.T) {
	unknownVersion := &config.Config{ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
		UserAgent: "claude-cli/9.9.9 (external, cli)",
	}}
	deprecatedFlag := &config.Config{ClaudeKey: []config.ClaudeKey{{ExperimentalCCHSigning: true}}}

	tests := []struct {
		name            string
		cfg             *config.Config
		firstPartyOAuth bool
		baseURL         string
		want            bool
	}{
		{name: "default first party API key", baseURL: "https://api.anthropic.com", want: false},
		{name: "empty first party API key base URL", baseURL: "", want: false},
		{name: "first party OAuth", firstPartyOAuth: true, baseURL: "https://api.anthropic.com", want: true},
		{name: "custom base URL", baseURL: "https://proxy.example.test", want: false},
		{name: "deprecated flag cannot override custom host", cfg: deprecatedFlag, baseURL: "https://proxy.example.test", want: false},
		{name: "unknown version", cfg: unknownVersion, baseURL: "https://api.anthropic.com", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := claudeCCHSigningEnabled(test.cfg, test.firstPartyOAuth, test.baseURL); got != test.want {
				t.Fatalf("claudeCCHSigningEnabled() = %v, want %v", got, test.want)
			}
		})
	}
}
