package common

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var emptyClaudeToolInputSchema = []byte(`{"type":"object","properties":{}}`)

// ClaudeSupportsMidConversationSystem reports whether the current first-party
// model accepts role=system entries inside messages without a beta header.
func ClaudeSupportsMidConversationSystem(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	return strings.Contains(model, "claude-fable-5") ||
		strings.Contains(model, "claude-mythos-5") ||
		strings.Contains(model, "claude-opus-4-8")
}

// NormalizeClaudeToolInputSchema returns a valid Anthropic tool input_schema
// while retaining the caller's raw JSON numbers and extension fields.
func NormalizeClaudeToolInputSchema(parameters gjson.Result) []byte {
	raw := strings.TrimSpace(parameters.Raw)
	if raw == "" || raw == "null" || !gjson.Valid(raw) {
		return bytesClone(emptyClaudeToolInputSchema)
	}
	result := gjson.Parse(raw)
	if !result.IsObject() {
		return bytesClone(emptyClaudeToolInputSchema)
	}

	schema := []byte(raw)
	schemaType := result.Get("type").String()
	if schemaType == "" {
		schema, _ = sjson.SetBytes(schema, "type", "object")
		schemaType = "object"
	}
	if schemaType == "object" && !result.Get("properties").Exists() {
		schema, _ = sjson.SetRawBytes(schema, "properties", []byte(`{}`))
	}
	return schema
}

func bytesClone(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
