package helps

import (
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestObfuscateSensitiveWordsPreservesGeneratedClaudeSystemBlocks(t *testing.T) {
	payload := []byte(`{"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=sdk-cli; cch=00000;"},{"type":"text","text":"You are a Claude agent, built on Anthropic's Claude Agent SDK."},{"type":"text","text":"Official Anthropic prompt"}],"messages":[{"role":"user","content":[{"type":"text","text":"customer mentions Anthropic and cch"}]}]}`)
	wantSystem := gjson.GetBytes(payload, "system").Raw

	out := ObfuscateSensitiveWords(payload, BuildSensitiveWordMatcher([]string{"anthropic", "entrypoint", "cch"}))

	if got := gjson.GetBytes(out, "system").Raw; got != wantSystem {
		t.Fatalf("generated Claude system blocks changed:\n got: %s\nwant: %s", got, wantSystem)
	}
	message := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !strings.Contains(message, zeroWidthSpace) {
		t.Fatalf("customer message was not obfuscated: %q", message)
	}
}

func TestObfuscateSensitiveWordsStillProcessesCustomerSystem(t *testing.T) {
	payload := []byte(`{"system":[{"type":"text","text":"customer proxy rule"}],"messages":[{"role":"user","content":"proxy access"}]}`)

	out := ObfuscateSensitiveWords(payload, BuildSensitiveWordMatcher([]string{"proxy"}))

	if got := gjson.GetBytes(out, "system.0.text").String(); !strings.Contains(got, zeroWidthSpace) {
		t.Fatalf("customer system text was not obfuscated: %q", got)
	}
	if got := gjson.GetBytes(out, "messages.0.content").String(); !strings.Contains(got, zeroWidthSpace) {
		t.Fatalf("customer message was not obfuscated: %q", got)
	}
}
