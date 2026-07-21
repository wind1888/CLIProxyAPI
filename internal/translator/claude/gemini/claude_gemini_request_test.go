package gemini

import (
	"fmt"
	"testing"

	"github.com/tidwall/gjson"
)

func TestConvertGeminiRequestToClaude_UsesNativeModelDefaultAndPreservesExplicitMax(t *testing.T) {
	implicit := ConvertGeminiRequestToClaude("claude-sonnet-5", []byte(`{
		"contents":[{"role":"user","parts":[{"text":"hi"}]}]
	}`), false)
	if got := gjson.GetBytes(implicit, "max_tokens").Int(); got != 64000 {
		t.Fatalf("implicit Sonnet 5 max_tokens = %d, want Claude Code default 64000: %s", got, implicit)
	}

	explicit := ConvertGeminiRequestToClaude("claude-sonnet-5", []byte(`{
		"generationConfig":{"maxOutputTokens":12345},
		"contents":[{"role":"user","parts":[{"text":"hi"}]}]
	}`), false)
	if got := gjson.GetBytes(explicit, "max_tokens").Int(); got != 12345 {
		t.Fatalf("explicit max_tokens = %d, want 12345: %s", got, explicit)
	}
}

func TestConvertGeminiRequestToClaude_PreservesCustomToolIDs(t *testing.T) {
	tests := []struct {
		name          string
		callField     string
		responseField string
		want          string
	}{
		{
			name:          "id",
			callField:     `"id":"call_gateway_id"`,
			responseField: `"id":"call_gateway_id"`,
			want:          "call_gateway_id",
		},
		{
			name:          "call_id",
			callField:     `"call_id":"call_gateway_call_id"`,
			responseField: `"call_id":"call_gateway_call_id"`,
			want:          "call_gateway_call_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{
				"contents": [
					{
						"role": "model",
						"parts": [
							{"functionCall": {"name": "lookup", %s, "args": {"query": "status"}}}
						]
					},
					{
						"role": "user",
						"parts": [
							{"functionResponse": {"name": "lookup", %s, "response": {"result": "ok"}}}
						]
					}
				]
			}`, tt.callField, tt.responseField))

			out := ConvertGeminiRequestToClaude("claude-sonnet-4", raw, false)

			gotCallID := gjson.GetBytes(out, "messages.0.content.0.id").String()
			if gotCallID != tt.want {
				t.Fatalf("expected tool_use id %q, got %q; output=%s", tt.want, gotCallID, string(out))
			}

			gotResultID := gjson.GetBytes(out, "messages.1.content.0.tool_use_id").String()
			if gotResultID != tt.want {
				t.Fatalf("expected tool_result tool_use_id %q, got %q; output=%s", tt.want, gotResultID, string(out))
			}
		})
	}
}

func TestConvertGeminiRequestToClaude_PreservesLargeToolSchemaIntegers(t *testing.T) {
	out := ConvertGeminiRequestToClaude("claude-sonnet-5", []byte(`{
		"contents":[{"role":"user","parts":[{"text":"hi"}]}],
		"tools":[{"functionDeclarations":[{
			"name":"lookup",
			"parameters":{"type":"OBJECT","properties":{"id":{"type":"INTEGER","const":9007199254740993}}}
		},{"name":"empty"}]}]
	}`), false)

	if got := gjson.GetBytes(out, "tools.0.input_schema.properties.id.const").Raw; got != "9007199254740993" {
		t.Fatalf("large schema integer = %s, want exact 9007199254740993: %s", got, out)
	}
	if got := gjson.GetBytes(out, "tools.0.input_schema.type").String(); got != "object" {
		t.Fatalf("schema type = %q, want object: %s", got, out)
	}
	if got := gjson.GetBytes(out, "tools.1.input_schema.type").String(); got != "object" {
		t.Fatalf("empty schema type = %q, want object: %s", got, out)
	}
}

func TestConvertGeminiRequestToClaude_MapsSystemInstructionAndDefaultsMissingRole(t *testing.T) {
	for _, field := range []string{"systemInstruction", "system_instruction"} {
		t.Run(field, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{
				%q:{"cache_control":{"type":"ephemeral"},"parts":[
					{"text":"first"},
					{"text":"second","cache_control":{"type":"ephemeral","ttl":"5m"}}
				]},
				"contents":[{"parts":[{"text":"hello"}]}]
			}`, field))
			out := ConvertGeminiRequestToClaude("claude-sonnet-5", raw, false)
			if got := gjson.GetBytes(out, "system.0.text").String(); got != "first" {
				t.Fatalf("system.0.text = %q, want first: %s", got, out)
			}
			if got := gjson.GetBytes(out, "system.1.text").String(); got != "second" {
				t.Fatalf("system.1.text = %q, want second: %s", got, out)
			}
			if got := gjson.GetBytes(out, "system.1.cache_control.ttl").String(); got != "5m" {
				t.Fatalf("part cache marker ttl = %q, want 5m: %s", got, out)
			}
			if got := gjson.GetBytes(out, "messages.0.role").String(); got != "user" {
				t.Fatalf("missing Gemini role mapped to %q, want user: %s", got, out)
			}
			if got := gjson.GetBytes(out, "messages.#").Int(); got != 1 {
				t.Fatalf("system instruction leaked into messages; count = %d: %s", got, out)
			}
		})
	}
}

func TestConvertGeminiRequestToClaude_DropsTemperature(t *testing.T) {
	raw := []byte(`{
		"generationConfig": {
			"temperature": 0.2,
			"topP": 0.8
		},
		"contents": [
			{
				"role": "user",
				"parts": [{"text": "hi"}]
			}
		]
	}`)

	out := ConvertGeminiRequestToClaude("claude-sonnet-5", raw, false)

	if gjson.GetBytes(out, "temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
	if got := gjson.GetBytes(out, "top_p").Float(); got != 0.8 {
		t.Fatalf("top_p = %v, want 0.8", got)
	}
}

func TestConvertGeminiRequestToClaude_MapsThinkingSummaryVisibilityWithoutEnablingThinking(t *testing.T) {
	visibilityOnly := ConvertGeminiRequestToClaude("claude-sonnet-4", []byte(`{
		"generationConfig":{"thinkingConfig":{"includeThoughts":true}},
		"contents":[{"role":"user","parts":[{"text":"hi"}]}]
	}`), false)
	if gjson.GetBytes(visibilityOnly, "thinking").Exists() {
		t.Fatalf("includeThoughts alone must not enable Claude thinking: %s", visibilityOnly)
	}

	tests := []struct {
		name            string
		includeThoughts string
		wantDisplay     string
	}{
		{name: "summarized", includeThoughts: `"includeThoughts":true`, wantDisplay: "summarized"},
		{name: "omitted", includeThoughts: `"includeThoughts":false`, wantDisplay: "omitted"},
		{name: "snake case omitted", includeThoughts: `"include_thoughts":false`, wantDisplay: "omitted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{
				"generationConfig":{"thinkingConfig":{"thinkingBudget":2048,%s}},
				"contents":[{"role":"user","parts":[{"text":"hi"}]}]
			}`, tt.includeThoughts))
			out := ConvertGeminiRequestToClaude("claude-sonnet-4", raw, false)
			if got := gjson.GetBytes(out, "thinking.type").String(); got != "enabled" {
				t.Fatalf("thinking.type = %q, want enabled: %s", got, out)
			}
			if got := gjson.GetBytes(out, "thinking.display").String(); got != tt.wantDisplay {
				t.Fatalf("thinking.display = %q, want %q: %s", got, tt.wantDisplay, out)
			}
		})
	}
}

func TestConvertGeminiRequestToClaude_MapsTopKAndPreservesUnionSchemaType(t *testing.T) {
	out := ConvertGeminiRequestToClaude("claude-sonnet-4", []byte(`{
		"generationConfig":{"topK":37},
		"contents":[{"role":"user","parts":[{"text":"hi"}]}],
		"tools":[{"functionDeclarations":[{
			"name":"lookup",
			"parametersJsonSchema":{
				"type":"OBJECT",
				"properties":{"value":{"type":["string","null"]}}
			}
		}]}]
	}`), false)

	if got := gjson.GetBytes(out, "top_k").Int(); got != 37 {
		t.Fatalf("top_k = %d, want 37: %s", got, out)
	}
	if got := gjson.GetBytes(out, "tools.0.input_schema.type").String(); got != "object" {
		t.Fatalf("string schema type = %q, want object: %s", got, out)
	}
	unionType := gjson.GetBytes(out, "tools.0.input_schema.properties.value.type")
	if !unionType.IsArray() || unionType.Raw != `["string","null"]` {
		t.Fatalf("union schema type = %s, want an unchanged JSON array: %s", unionType.Raw, out)
	}
}

func TestConvertGeminiRequestToClaude_AcceptsCamelInlineData(t *testing.T) {
	out := ConvertGeminiRequestToClaude("claude-sonnet-4", []byte(`{"contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"image/png","data":"aGVsbG8="}}]}]}`), false)
	if got := gjson.GetBytes(out, "messages.0.content.0.type").String(); got != "image" {
		t.Fatalf("content type = %q, want image. Output: %s", got, string(out))
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.source.media_type").String(); got != "image/png" {
		t.Fatalf("media_type = %q, want image/png. Output: %s", got, string(out))
	}
}

func TestConvertGeminiRequestToClaude_SplitsNonImageInlineDataByMIME(t *testing.T) {
	out := ConvertGeminiRequestToClaude("claude-sonnet-4", []byte(`{"contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"audio/wav","data":"UklGRg=="}},{"inlineData":{"mimeType":"video/mp4","data":"AAAAIGZ0eXA="}},{"inlineData":{"mimeType":"application/pdf","data":"JVBERi0="}}]}]}`), false)

	if got := gjson.GetBytes(out, "messages.0.content.0.type").String(); got != "text" {
		t.Fatalf("audio fallback type = %q, want text. Output: %s", got, string(out))
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.type").String(); got != "text" {
		t.Fatalf("video fallback type = %q, want text. Output: %s", got, string(out))
	}
	if got := gjson.GetBytes(out, "messages.0.content.2.type").String(); got != "document" {
		t.Fatalf("document content type = %q, want document. Output: %s", got, string(out))
	}
	if gjson.GetBytes(out, "messages.0.content.#(type==\"image\")").Exists() {
		t.Fatalf("non-image inlineData must not be converted to image. Output: %s", string(out))
	}
}
