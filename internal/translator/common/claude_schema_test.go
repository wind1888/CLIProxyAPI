package common

import (
	"testing"

	"github.com/tidwall/gjson"
)

func TestNormalizeClaudeToolInputSchema(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "missing", want: `{"type":"object","properties":{}}`},
		{name: "null", raw: `null`, want: `{"type":"object","properties":{}}`},
		{name: "non object", raw: `[]`, want: `{"type":"object","properties":{}}`},
		{name: "empty object", raw: `{}`, want: `{"type":"object","properties":{}}`},
		{name: "preserves exact integer", raw: `{"properties":{"id":{"const":9007199254740993}}}`, want: `{"properties":{"id":{"const":9007199254740993}},"type":"object"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var input gjson.Result
			if tc.raw != "" {
				input = gjson.Parse(tc.raw)
			}
			if got := string(NormalizeClaudeToolInputSchema(input)); got != tc.want {
				t.Fatalf("NormalizeClaudeToolInputSchema() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestClaudeSupportsMidConversationSystem(t *testing.T) {
	for model, want := range map[string]bool{
		"claude-fable-5":    true,
		"claude-mythos-5":   true,
		"claude-opus-4-8":   true,
		"claude-sonnet-5":   false,
		"claude-opus-4-7":   false,
		"claude-sonnet-4-6": false,
	} {
		if got := ClaudeSupportsMidConversationSystem(model); got != want {
			t.Errorf("ClaudeSupportsMidConversationSystem(%q) = %t, want %t", model, got, want)
		}
	}
}
