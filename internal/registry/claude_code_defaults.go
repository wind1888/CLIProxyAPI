package registry

import "strings"

// ClaudeCodeDefaultMaxTokens returns the model-specific max_tokens value used
// by Claude Code 2.1.216 when the caller does not provide an override.
func ClaudeCodeDefaultMaxTokens(modelID string) int {
	model := strings.ToLower(strings.TrimSpace(modelID))
	switch {
	case strings.Contains(model, "claude-3-5-haiku"):
		return 8192
	case strings.Contains(model, "claude-3-haiku"):
		return 4096
	case strings.Contains(model, "claude-haiku-4-5"):
		return 32000
	case strings.Contains(model, "claude-3-5-sonnet"):
		return 8192
	case strings.Contains(model, "claude-3-7-sonnet"):
		return 32000
	case strings.Contains(model, "claude-3-sonnet"):
		return 8192
	case strings.Contains(model, "claude-3-opus"):
		return 4096
	case strings.Contains(model, "claude-sonnet-5"),
		strings.Contains(model, "claude-fable-5"),
		strings.Contains(model, "claude-mythos-5"):
		return 64000
	case strings.Contains(model, "claude-sonnet-4-"):
		return 32000
	case strings.Contains(model, "claude-opus-4-6"),
		strings.Contains(model, "claude-opus-4-7"),
		strings.Contains(model, "claude-opus-4-8"):
		return 64000
	case strings.Contains(model, "claude-opus-4-"):
		return 32000
	default:
		if model != "" {
			return 32000
		}
		return 0
	}
}
