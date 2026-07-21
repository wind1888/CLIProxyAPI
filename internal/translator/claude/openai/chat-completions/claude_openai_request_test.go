package chat_completions

import (
	"fmt"
	"testing"

	"github.com/tidwall/gjson"
)

func TestConvertOpenAIRequestToClaude_UsesNativeModelDefaultAndModernMaxField(t *testing.T) {
	implicit := ConvertOpenAIRequestToClaude("claude-opus-4-8", []byte(`{
		"messages":[{"role":"user","content":"hi"}]
	}`), false)
	if got := gjson.GetBytes(implicit, "max_tokens").Int(); got != 64000 {
		t.Fatalf("implicit Opus 4.8 max_tokens = %d, want Claude Code default 64000: %s", got, implicit)
	}

	explicit := ConvertOpenAIRequestToClaude("claude-opus-4-8", []byte(`{
		"max_completion_tokens":12345,
		"messages":[{"role":"user","content":"hi"}]
	}`), false)
	if got := gjson.GetBytes(explicit, "max_tokens").Int(); got != 12345 {
		t.Fatalf("max_completion_tokens mapping = %d, want 12345: %s", got, explicit)
	}
}

func TestConvertOpenAIRequestToClaude_SanitizesToolCallIDsForClaude(t *testing.T) {
	inputJSON := `{
		"model": "gpt-4.1",
		"messages": [
			{
				"role": "assistant",
				"tool_calls": [
					{
						"id": "call.with space:1",
						"type": "function",
						"function": {
							"name": "Read",
							"arguments": "{\"path\":\"README.md\"}"
						}
					}
				]
			},
			{
				"role": "tool",
				"tool_call_id": "call.with space:1",
				"content": "ok"
			}
		]
	}`

	result := ConvertOpenAIRequestToClaude("claude-sonnet-4-5", []byte(inputJSON), false)
	resultJSON := gjson.ParseBytes(result)
	toolUseID := resultJSON.Get("messages.0.content.0.id").String()
	toolResultID := resultJSON.Get("messages.1.content.0.tool_use_id").String()

	if toolUseID != "call_with_space_1" {
		t.Fatalf("tool_use id = %q, want %q", toolUseID, "call_with_space_1")
	}
	if toolResultID != toolUseID {
		t.Fatalf("tool_result tool_use_id = %q, want same sanitized id %q", toolResultID, toolUseID)
	}
}

func TestConvertOpenAIRequestToClaude_DropsTemperature(t *testing.T) {
	inputJSON := `{
		"model": "gpt-4.1",
		"temperature": 0.2,
		"top_p": 0.8,
		"messages": [
			{"role": "user", "content": "hi"}
		]
	}`

	result := ConvertOpenAIRequestToClaude("claude-sonnet-5", []byte(inputJSON), false)
	resultJSON := gjson.ParseBytes(result)

	if resultJSON.Get("temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
	if got := resultJSON.Get("top_p").Float(); got != 0.8 {
		t.Fatalf("top_p = %v, want 0.8", got)
	}
}

func TestConvertOpenAIRequestToClaude_ToolResultTextAndBase64Image(t *testing.T) {
	inputJSON := `{
		"model": "gpt-4.1",
		"messages": [
			{
				"role": "assistant",
				"content": "",
				"tool_calls": [
					{
						"id": "call_1",
						"type": "function",
						"function": {
							"name": "do_work",
							"arguments": "{\"a\":1}"
						}
					}
				]
			},
			{
				"role": "tool",
				"tool_call_id": "call_1",
				"content": [
					{"type": "text", "text": "tool ok"},
					{
						"type": "image_url",
						"image_url": {
							"url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="
						}
					}
				]
			}
		]
	}`

	result := ConvertOpenAIRequestToClaude("claude-sonnet-4-5", []byte(inputJSON), false)
	resultJSON := gjson.ParseBytes(result)
	messages := resultJSON.Get("messages").Array()

	if len(messages) != 2 {
		t.Fatalf("Expected 2 messages, got %d. Messages: %s", len(messages), resultJSON.Get("messages").Raw)
	}

	toolResult := messages[1].Get("content.0")
	if got := toolResult.Get("type").String(); got != "tool_result" {
		t.Fatalf("Expected content[0].type %q, got %q", "tool_result", got)
	}
	if got := toolResult.Get("tool_use_id").String(); got != "call_1" {
		t.Fatalf("Expected tool_use_id %q, got %q", "call_1", got)
	}

	toolContent := toolResult.Get("content")
	if !toolContent.IsArray() {
		t.Fatalf("Expected tool_result content array, got %s", toolContent.Raw)
	}
	if got := toolContent.Get("0.type").String(); got != "text" {
		t.Fatalf("Expected first tool_result part type %q, got %q", "text", got)
	}
	if got := toolContent.Get("0.text").String(); got != "tool ok" {
		t.Fatalf("Expected first tool_result part text %q, got %q", "tool ok", got)
	}
	if got := toolContent.Get("1.type").String(); got != "image" {
		t.Fatalf("Expected second tool_result part type %q, got %q", "image", got)
	}
	if got := toolContent.Get("1.source.type").String(); got != "base64" {
		t.Fatalf("Expected image source type %q, got %q", "base64", got)
	}
	if got := toolContent.Get("1.source.media_type").String(); got != "image/png" {
		t.Fatalf("Expected image media type %q, got %q", "image/png", got)
	}
	if got := toolContent.Get("1.source.data").String(); got != "iVBORw0KGgoAAAANSUhEUg==" {
		t.Fatalf("Unexpected base64 image data: %q", got)
	}
}

func TestConvertOpenAIRequestToClaude_ToolResultURLImageOnly(t *testing.T) {
	inputJSON := `{
		"model": "gpt-4.1",
		"messages": [
			{
				"role": "assistant",
				"content": "",
				"tool_calls": [
					{
						"id": "call_1",
						"type": "function",
						"function": {
							"name": "do_work",
							"arguments": "{\"a\":1}"
						}
					}
				]
			},
			{
				"role": "tool",
				"tool_call_id": "call_1",
				"content": [
					{
						"type": "image_url",
						"image_url": {
							"url": "https://example.com/tool.png"
						}
					}
				]
			}
		]
	}`

	result := ConvertOpenAIRequestToClaude("claude-sonnet-4-5", []byte(inputJSON), false)
	resultJSON := gjson.ParseBytes(result)
	messages := resultJSON.Get("messages").Array()

	if len(messages) != 2 {
		t.Fatalf("Expected 2 messages, got %d. Messages: %s", len(messages), resultJSON.Get("messages").Raw)
	}

	toolContent := messages[1].Get("content.0.content")
	if !toolContent.IsArray() {
		t.Fatalf("Expected tool_result content array, got %s", toolContent.Raw)
	}
	if got := toolContent.Get("0.type").String(); got != "image" {
		t.Fatalf("Expected tool_result part type %q, got %q", "image", got)
	}
	if got := toolContent.Get("0.source.type").String(); got != "url" {
		t.Fatalf("Expected image source type %q, got %q", "url", got)
	}
	if got := toolContent.Get("0.source.url").String(); got != "https://example.com/tool.png" {
		t.Fatalf("Unexpected image URL: %q", got)
	}
}

func TestConvertOpenAIRequestToClaude_SystemRoleBecomesTopLevelSystem(t *testing.T) {
	inputJSON := `{
		"model": "gpt-4.1",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "Hello"}
		]
	}`

	result := ConvertOpenAIRequestToClaude("claude-sonnet-4-5", []byte(inputJSON), false)
	resultJSON := gjson.ParseBytes(result)

	system := resultJSON.Get("system")
	if !system.IsArray() {
		t.Fatalf("Expected top-level system array, got %s", system.Raw)
	}
	if len(system.Array()) != 1 {
		t.Fatalf("Expected 1 system block, got %d. System: %s", len(system.Array()), system.Raw)
	}
	if got := system.Get("0.type").String(); got != "text" {
		t.Fatalf("Expected system block type %q, got %q", "text", got)
	}
	if got := system.Get("0.text").String(); got != "You are a helpful assistant." {
		t.Fatalf("Expected system text %q, got %q", "You are a helpful assistant.", got)
	}

	messages := resultJSON.Get("messages").Array()
	if len(messages) != 1 {
		t.Fatalf("Expected 1 non-system message, got %d. Messages: %s", len(messages), resultJSON.Get("messages").Raw)
	}
	if got := messages[0].Get("role").String(); got != "user" {
		t.Fatalf("Expected remaining message role %q, got %q", "user", got)
	}
	if got := messages[0].Get("content.0.text").String(); got != "Hello" {
		t.Fatalf("Expected user text %q, got %q", "Hello", got)
	}
}

func TestConvertOpenAIRequestToClaude_MultipleSystemMessagesMergedIntoTopLevelSystem(t *testing.T) {
	inputJSON := `{
		"model": "gpt-4.1",
		"messages": [
			{"role": "system", "content": "Rule 1"},
			{"role": "system", "content": [{"type": "text", "text": "Rule 2"}]},
			{"role": "user", "content": "Hello"}
		]
	}`

	result := ConvertOpenAIRequestToClaude("claude-sonnet-4-5", []byte(inputJSON), false)
	resultJSON := gjson.ParseBytes(result)

	system := resultJSON.Get("system").Array()
	if len(system) != 2 {
		t.Fatalf("Expected 2 system blocks, got %d. System: %s", len(system), resultJSON.Get("system").Raw)
	}
	if got := system[0].Get("text").String(); got != "Rule 1" {
		t.Fatalf("Expected first system text %q, got %q", "Rule 1", got)
	}
	if got := system[1].Get("text").String(); got != "Rule 2" {
		t.Fatalf("Expected second system text %q, got %q", "Rule 2", got)
	}

	messages := resultJSON.Get("messages").Array()
	if len(messages) != 1 {
		t.Fatalf("Expected 1 non-system message, got %d. Messages: %s", len(messages), resultJSON.Get("messages").Raw)
	}
	if got := messages[0].Get("role").String(); got != "user" {
		t.Fatalf("Expected remaining message role %q, got %q", "user", got)
	}
	if got := messages[0].Get("content.0.text").String(); got != "Hello" {
		t.Fatalf("Expected user text %q, got %q", "Hello", got)
	}
}

func TestConvertOpenAIRequestToClaude_SystemOnlyInputKeepsFallbackUserMessage(t *testing.T) {
	inputJSON := `{
		"model": "gpt-4.1",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."}
		]
	}`

	result := ConvertOpenAIRequestToClaude("claude-sonnet-4-5", []byte(inputJSON), false)
	resultJSON := gjson.ParseBytes(result)

	system := resultJSON.Get("system").Array()
	if len(system) != 1 {
		t.Fatalf("Expected 1 system block, got %d. System: %s", len(system), resultJSON.Get("system").Raw)
	}
	if got := system[0].Get("text").String(); got != "You are a helpful assistant." {
		t.Fatalf("Expected system text %q, got %q", "You are a helpful assistant.", got)
	}

	messages := resultJSON.Get("messages").Array()
	if len(messages) != 1 {
		t.Fatalf("Expected 1 fallback message, got %d. Messages: %s", len(messages), resultJSON.Get("messages").Raw)
	}
	if got := messages[0].Get("role").String(); got != "user" {
		t.Fatalf("Expected fallback message role %q, got %q", "user", got)
	}
	if got := messages[0].Get("content.0.type").String(); got != "text" {
		t.Fatalf("Expected fallback content type %q, got %q", "text", got)
	}
	if got := messages[0].Get("content.0.text").String(); got != "\u200b" {
		t.Fatalf("Expected non-empty minimal fallback text, got %q", got)
	}
}

func TestConvertOpenAIRequestToClaude_DropsEmptyTextBlocks(t *testing.T) {
	out := ConvertOpenAIRequestToClaude("claude-sonnet-5", []byte(`{
		"messages":[
			{"role":"user","content":[{"type":"text","text":""},{"type":"text","text":"hello"}]},
			{"role":"assistant","content":""}
		]
	}`), false)
	if got := gjson.GetBytes(out, "messages.#").Int(); got != 1 {
		t.Fatalf("messages count = %d, want only non-empty turn: %s", got, out)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.text").String(); got != "hello" {
		t.Fatalf("remaining text = %q, want hello: %s", got, out)
	}
}

func TestConvertOpenAIRequestToClaude_PreservesContentPartCacheControl(t *testing.T) {
	inputJSON := `{
		"model": "gpt-4.1",
		"messages": [
			{
				"role": "user",
				"content": [
					{"type": "text", "text": "cached prefix", "cache_control": {"type": "ephemeral"}},
					{"type": "text", "text": "fresh question"}
				]
			}
		]
	}`

	result := ConvertOpenAIRequestToClaude("claude-sonnet-4-5", []byte(inputJSON), false)
	resultJSON := gjson.ParseBytes(result)

	if got := resultJSON.Get("messages.0.content.0.cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("content.0.cache_control.type = %q, want ephemeral. Output: %s", got, result)
	}
	if resultJSON.Get("messages.0.content.1.cache_control").Exists() {
		t.Fatalf("content.1 should not have cache_control. Output: %s", result)
	}
	if got := resultJSON.Get("messages.0.content.0.text").String(); got != "cached prefix" {
		t.Fatalf("content.0.text = %q, want %q", got, "cached prefix")
	}
}

func TestConvertOpenAIRequestToClaude_MapsDeveloperMessagesToTopLevelSystem(t *testing.T) {
	inputJSON := `{
		"messages": [
			{"role":"system","content":"base policy"},
			{"role":"developer","content":[
				{"type":"text","text":"cached developer policy"},
				{"type":"text","text":"final developer policy"}
			],"cache_control":{"type":"ephemeral"}},
			{"role":"user","content":"hello"}
		]
	}`

	out := ConvertOpenAIRequestToClaude("claude-sonnet-5", []byte(inputJSON), false)
	root := gjson.ParseBytes(out)
	if got := root.Get("system.#").Int(); got != 3 {
		t.Fatalf("system block count = %d, want 3: %s", got, out)
	}
	for index, want := range []string{"base policy", "cached developer policy", "final developer policy"} {
		if got := root.Get(fmt.Sprintf("system.%d.text", index)).String(); got != want {
			t.Fatalf("system.%d.text = %q, want %q: %s", index, got, want, out)
		}
	}
	if got := root.Get("system.2.cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("message cache marker = %q, want ephemeral: %s", got, out)
	}
	if got := root.Get("messages.#").Int(); got != 1 {
		t.Fatalf("messages count = %d, want only user turn: %s", got, out)
	}
}

func TestConvertOpenAIRequestToClaude_PreservesSupportedMidConversationSystem(t *testing.T) {
	request := []byte(`{"messages":[
		{"role":"user","content":"question"},
		{"role":"developer","content":"new operator rule"},
		{"role":"assistant","content":"answer"}
	]}`)

	supported := ConvertOpenAIRequestToClaude("claude-fable-5", request, false)
	for index, want := range []string{"user", "system", "assistant"} {
		if got := gjson.GetBytes(supported, fmt.Sprintf("messages.%d.role", index)).String(); got != want {
			t.Fatalf("supported messages.%d.role = %q, want %q: %s", index, got, want, supported)
		}
	}
	if got := gjson.GetBytes(supported, "messages.1.content.0.text").String(); got != "new operator rule" {
		t.Fatalf("mid-conversation system text = %q: %s", got, supported)
	}
	if gjson.GetBytes(supported, "system").Exists() {
		t.Fatalf("supported mid-conversation rule was promoted: %s", supported)
	}

	unsupported := ConvertOpenAIRequestToClaude("claude-sonnet-5", request, false)
	if got := gjson.GetBytes(unsupported, "system.0.text").String(); got != "new operator rule" {
		t.Fatalf("Sonnet 5 fallback system text = %q: %s", got, unsupported)
	}
	if got := gjson.GetBytes(unsupported, "messages.#").Int(); got != 2 {
		t.Fatalf("Sonnet 5 messages count = %d, want user+assistant: %s", got, unsupported)
	}
}

func TestConvertOpenAIRequestToClaude_NormalizesToolInputSchema(t *testing.T) {
	out := ConvertOpenAIRequestToClaude("claude-sonnet-5", []byte(`{
		"messages":[{"role":"user","content":"hi"}],
		"tools":[
			{"type":"function","function":{"name":"empty"}},
			{"type":"function","function":{"name":"exact","parameters":{"properties":{"id":{"const":9007199254740993}}}}}
		]
	}`), false)
	root := gjson.ParseBytes(out)
	for index := 0; index < 2; index++ {
		if got := root.Get(fmt.Sprintf("tools.%d.input_schema.type", index)).String(); got != "object" {
			t.Fatalf("tools.%d schema type = %q, want object: %s", index, got, out)
		}
	}
	if got := root.Get("tools.1.input_schema.properties.id.const").Raw; got != "9007199254740993" {
		t.Fatalf("large schema integer = %s, want exact 9007199254740993: %s", got, out)
	}
}

func TestConvertOpenAIRequestToClaude_PreservesToolControlSemantics(t *testing.T) {
	none := ConvertOpenAIRequestToClaude("claude-sonnet-5", []byte(`{
		"messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","function":{"name":"lookup","strict":true}}],
		"tool_choice":"none",
		"parallel_tool_calls":false
	}`), false)
	if got := gjson.GetBytes(none, "tools.0.strict").Bool(); !got {
		t.Fatalf("strict tool flag was lost: %s", none)
	}
	if got := gjson.GetBytes(none, "tool_choice.type").String(); got != "none" {
		t.Fatalf("tool_choice.type = %q, want none: %s", got, none)
	}
	if gjson.GetBytes(none, "tool_choice.disable_parallel_tool_use").Exists() {
		t.Fatalf("none choice must not carry parallel-use flag: %s", none)
	}

	serial := ConvertOpenAIRequestToClaude("claude-sonnet-5", []byte(`{
		"messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","function":{"name":"lookup"}}],
		"parallel_tool_calls":false
	}`), false)
	if got := gjson.GetBytes(serial, "tool_choice.type").String(); got != "auto" {
		t.Fatalf("implicit tool_choice.type = %q, want auto: %s", got, serial)
	}
	if !gjson.GetBytes(serial, "tool_choice.disable_parallel_tool_use").Bool() {
		t.Fatalf("parallel_tool_calls=false was lost: %s", serial)
	}
}

func TestConvertOpenAIRequestToClaude_PreservesMessageLevelCacheControl(t *testing.T) {
	inputJSON := `{
		"model": "gpt-4.1",
		"messages": [
			{
				"role": "user",
				"content": "cache me",
				"cache_control": {"type": "ephemeral", "ttl": "1h"}
			}
		]
	}`

	result := ConvertOpenAIRequestToClaude("claude-sonnet-4-5", []byte(inputJSON), false)
	resultJSON := gjson.ParseBytes(result)

	if got := resultJSON.Get("messages.0.content.0.cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("content.0.cache_control.type = %q, want ephemeral. Output: %s", got, result)
	}
	if got := resultJSON.Get("messages.0.content.0.cache_control.ttl").String(); got != "1h" {
		t.Fatalf("content.0.cache_control.ttl = %q, want 1h. Output: %s", got, result)
	}
}

func TestConvertOpenAIRequestToClaude_PreservesToolCacheControl(t *testing.T) {
	inputJSON := `{
		"model": "gpt-4.1",
		"messages": [{"role": "user", "content": "hi"}],
		"tools": [
			{
				"type": "function",
				"function": {
					"name": "lookup",
					"description": "Lookup something",
					"parameters": {"type": "object", "properties": {}}
				},
				"cache_control": {"type": "ephemeral"}
			}
		]
	}`

	result := ConvertOpenAIRequestToClaude("claude-sonnet-4-5", []byte(inputJSON), false)
	resultJSON := gjson.ParseBytes(result)

	if got := resultJSON.Get("tools.0.cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("tools.0.cache_control.type = %q, want ephemeral. Output: %s", got, result)
	}
	if got := resultJSON.Get("tools.0.name").String(); got != "lookup" {
		t.Fatalf("tools.0.name = %q, want lookup", got)
	}
}

func TestConvertOpenAIRequestToClaude_PartCacheControlWinsOverMessageLevel(t *testing.T) {
	inputJSON := `{
		"model": "gpt-4.1",
		"messages": [
			{
				"role": "user",
				"cache_control": {"type": "ephemeral", "ttl": "1h"},
				"content": [
					{"type": "text", "text": "part cached", "cache_control": {"type": "ephemeral"}}
				]
			}
		]
	}`

	result := ConvertOpenAIRequestToClaude("claude-sonnet-4-5", []byte(inputJSON), false)
	resultJSON := gjson.ParseBytes(result)

	if got := resultJSON.Get("messages.0.content.0.cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("content.0.cache_control.type = %q, want ephemeral. Output: %s", got, result)
	}
	if resultJSON.Get("messages.0.content.0.cache_control.ttl").Exists() {
		t.Fatalf("part-level cache_control should win; unexpected ttl: %s", result)
	}
}
