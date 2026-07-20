package executor

import (
	"bytes"
	"os"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
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
	// Public Claude Code 2.1.177 capture from askalf/dario#528. Claude Code
	// 2.1.215 uses the same native projection and seed.
	want, errRead := os.ReadFile("testdata/cch-cc2.1.177.json")
	if errRead != nil {
		t.Fatal(errRead)
	}

	input := bytes.Replace(want, []byte("cch=a82da;"), []byte("cch=fffff;"), 1)
	got := mustSignAnthropicMessagesBody(t, input)
	if !bytes.Equal(got, want) {
		t.Fatalf("signed body does not match official golden\nwant: %s\n got: %s", want, got)
	}
	if gotAgain := mustSignAnthropicMessagesBody(t, got); !bytes.Equal(gotAgain, got) {
		t.Fatalf("signing is not idempotent\nfirst:  %s\nsecond: %s", got, gotAgain)
	}
}

func TestSignAnthropicMessagesBodyUsesOfficialProjection(t *testing.T) {
	base, errRead := os.ReadFile("testdata/cch-cc2.1.177.json")
	if errRead != nil {
		t.Fatal(errRead)
	}
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

	for name, invalid := range map[string][]byte{
		"missing billing": []byte(`{"model":"claude-sonnet-4","messages":[]}`),
		"malformed json":  append(bytes.Clone(body), '{'),
	} {
		t.Run(name, func(t *testing.T) {
			got, errSign := signAnthropicMessagesBody(invalid)
			if errSign == nil {
				t.Fatal("signAnthropicMessagesBody() error = nil")
			}
			if !bytes.Equal(got, invalid) {
				t.Fatalf("invalid body changed\nwant: %s\n got: %s", invalid, got)
			}
		})
	}
}

func TestSignAnthropicMessagesBodyRejectsUncalibratedVersion(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4","messages":[],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=9.9.9.abc; cc_entrypoint=sdk-cli; cch=00000;"}],"max_tokens":32000}`)

	got, errSign := signAnthropicMessagesBody(body)
	if errSign == nil {
		t.Fatal("signAnthropicMessagesBody() error = nil")
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("uncalibrated body changed\nwant: %s\n got: %s", body, got)
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
		{name: "default first party API key", baseURL: "https://api.anthropic.com", want: true},
		{name: "empty first party base URL", baseURL: "", want: true},
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
