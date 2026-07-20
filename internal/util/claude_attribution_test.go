package util

import "testing"

func TestIsClaudeCodeAttributionSystemText(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{
			name: "Claude Code attribution block",
			text: "x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=cli;",
			want: true,
		},
		{
			name: "leading whitespace",
			text: "\n\t x-anthropic-billing-header: cc_version=2.1.215.d68; cc_entrypoint=cli;",
			want: true,
		},
		{
			name: "regular system prompt",
			text: "You are helpful.",
			want: false,
		},
		{
			name: "empty text",
			text: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsClaudeCodeAttributionSystemText(tt.text); got != tt.want {
				t.Fatalf("IsClaudeCodeAttributionSystemText(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}
