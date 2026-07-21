package chat_completions

import (
	"context"
	"testing"

	"github.com/tidwall/gjson"
)

func TestConvertClaudeResponseToOpenAI_StreamUsageIncludesCachedTokens(t *testing.T) {
	ctx := context.Background()
	var param any

	out := ConvertClaudeResponseToOpenAI(
		ctx,
		"claude-opus-4-6",
		nil,
		nil,
		[]byte(`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":13,"output_tokens":4,"cache_read_input_tokens":22000,"cache_creation_input_tokens":31}}`),
		&param,
	)
	if len(out) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(out))
	}

	if gotPromptTokens := gjson.GetBytes(out[0], "usage.prompt_tokens").Int(); gotPromptTokens != 22044 {
		t.Fatalf("expected prompt_tokens %d, got %d", 22044, gotPromptTokens)
	}
	if gotCompletionTokens := gjson.GetBytes(out[0], "usage.completion_tokens").Int(); gotCompletionTokens != 4 {
		t.Fatalf("expected completion_tokens %d, got %d", 4, gotCompletionTokens)
	}
	if gotTotalTokens := gjson.GetBytes(out[0], "usage.total_tokens").Int(); gotTotalTokens != 22048 {
		t.Fatalf("expected total_tokens %d, got %d", 22048, gotTotalTokens)
	}
	if gotCachedTokens := gjson.GetBytes(out[0], "usage.prompt_tokens_details.cached_tokens").Int(); gotCachedTokens != 22000 {
		t.Fatalf("expected cached_tokens %d, got %d", 22000, gotCachedTokens)
	}
}

func TestConvertClaudeResponseToOpenAI_StreamUsageMergesMessageStartUsage(t *testing.T) {
	ctx := context.Background()
	var param any

	ConvertClaudeResponseToOpenAI(
		ctx,
		"claude-opus-4-6",
		nil,
		nil,
		[]byte(`data: {"type":"message_start","message":{"id":"msg_123","model":"claude-opus-4-6","usage":{"input_tokens":13,"output_tokens":1,"cache_read_input_tokens":22000,"cache_creation_input_tokens":31}}}`),
		&param,
	)
	out := ConvertClaudeResponseToOpenAI(
		ctx,
		"claude-opus-4-6",
		nil,
		nil,
		[]byte(`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":null,"output_tokens":4,"cache_read_input_tokens":null,"cache_creation_input_tokens":null}}`),
		&param,
	)
	if len(out) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(out))
	}

	if gotPromptTokens := gjson.GetBytes(out[0], "usage.prompt_tokens").Int(); gotPromptTokens != 22044 {
		t.Fatalf("expected prompt_tokens %d, got %d", 22044, gotPromptTokens)
	}
	if gotCompletionTokens := gjson.GetBytes(out[0], "usage.completion_tokens").Int(); gotCompletionTokens != 4 {
		t.Fatalf("expected completion_tokens %d, got %d", 4, gotCompletionTokens)
	}
	if gotTotalTokens := gjson.GetBytes(out[0], "usage.total_tokens").Int(); gotTotalTokens != 22048 {
		t.Fatalf("expected total_tokens %d, got %d", 22048, gotTotalTokens)
	}
	if gotCachedTokens := gjson.GetBytes(out[0], "usage.prompt_tokens_details.cached_tokens").Int(); gotCachedTokens != 22000 {
		t.Fatalf("expected cached_tokens %d, got %d", 22000, gotCachedTokens)
	}
}

func TestConvertClaudeResponseToOpenAI_StreamNullStopReasonOnlyUpdatesUsage(t *testing.T) {
	ctx := context.Background()
	var param any

	out := ConvertClaudeResponseToOpenAI(
		ctx,
		"claude-fable-5",
		nil,
		nil,
		[]byte(`data: {"type":"message_delta","delta":{"stop_reason":null,"stop_sequence":null},"usage":{"output_tokens":9}}`),
		&param,
	)
	if len(out) != 1 {
		t.Fatalf("expected 1 usage chunk, got %d", len(out))
	}
	if got := gjson.GetBytes(out[0], "choices.0.finish_reason"); got.Raw != "null" {
		t.Fatalf("finish_reason = %s, want null", got.Raw)
	}
	if got := gjson.GetBytes(out[0], "usage.completion_tokens").Int(); got != 9 {
		t.Fatalf("completion_tokens = %d, want 9", got)
	}

	out = ConvertClaudeResponseToOpenAI(
		ctx,
		"claude-fable-5",
		nil,
		nil,
		[]byte(`data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":10}}`),
		&param,
	)
	if len(out) != 1 {
		t.Fatalf("expected 1 final chunk, got %d", len(out))
	}
	if got := gjson.GetBytes(out[0], "choices.0.finish_reason").String(); got != "stop" {
		t.Fatalf("finish_reason = %q, want stop", got)
	}
	if got := gjson.GetBytes(out[0], "usage.completion_tokens").Int(); got != 10 {
		t.Fatalf("completion_tokens = %d, want 10", got)
	}
}

func TestConvertClaudeResponseToOpenAINonStream_UsageIncludesCachedTokens(t *testing.T) {
	rawJSON := []byte("data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_123\",\"model\":\"claude-opus-4-6\"}}\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":13,\"output_tokens\":4,\"cache_read_input_tokens\":22000,\"cache_creation_input_tokens\":31}}\n")

	out := ConvertClaudeResponseToOpenAINonStream(context.Background(), "", nil, nil, rawJSON, nil)

	if gotPromptTokens := gjson.GetBytes(out, "usage.prompt_tokens").Int(); gotPromptTokens != 22044 {
		t.Fatalf("expected prompt_tokens %d, got %d", 22044, gotPromptTokens)
	}
	if gotCompletionTokens := gjson.GetBytes(out, "usage.completion_tokens").Int(); gotCompletionTokens != 4 {
		t.Fatalf("expected completion_tokens %d, got %d", 4, gotCompletionTokens)
	}
	if gotTotalTokens := gjson.GetBytes(out, "usage.total_tokens").Int(); gotTotalTokens != 22048 {
		t.Fatalf("expected total_tokens %d, got %d", 22048, gotTotalTokens)
	}
	if gotCachedTokens := gjson.GetBytes(out, "usage.prompt_tokens_details.cached_tokens").Int(); gotCachedTokens != 22000 {
		t.Fatalf("expected cached_tokens %d, got %d", 22000, gotCachedTokens)
	}
}

func TestConvertClaudeResponseToOpenAINonStream_UsageMergesMessageStartUsage(t *testing.T) {
	rawJSON := []byte("data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_123\",\"model\":\"claude-opus-4-6\",\"usage\":{\"input_tokens\":13,\"output_tokens\":1,\"cache_read_input_tokens\":22000,\"cache_creation_input_tokens\":31}}}\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":null,\"output_tokens\":4,\"cache_read_input_tokens\":null,\"cache_creation_input_tokens\":null}}\n")

	out := ConvertClaudeResponseToOpenAINonStream(context.Background(), "", nil, nil, rawJSON, nil)

	if gotPromptTokens := gjson.GetBytes(out, "usage.prompt_tokens").Int(); gotPromptTokens != 22044 {
		t.Fatalf("expected prompt_tokens %d, got %d", 22044, gotPromptTokens)
	}
	if gotCompletionTokens := gjson.GetBytes(out, "usage.completion_tokens").Int(); gotCompletionTokens != 4 {
		t.Fatalf("expected completion_tokens %d, got %d", 4, gotCompletionTokens)
	}
	if gotTotalTokens := gjson.GetBytes(out, "usage.total_tokens").Int(); gotTotalTokens != 22048 {
		t.Fatalf("expected total_tokens %d, got %d", 22048, gotTotalTokens)
	}
	if gotCachedTokens := gjson.GetBytes(out, "usage.prompt_tokens_details.cached_tokens").Int(); gotCachedTokens != 22000 {
		t.Fatalf("expected cached_tokens %d, got %d", 22000, gotCachedTokens)
	}
}

func TestConvertClaudeResponseToOpenAI_FallbackBoundaryIsIgnoredWithoutPhantomOutput(t *testing.T) {
	ctx := context.Background()
	var param any

	ConvertClaudeResponseToOpenAI(ctx, "claude-fable-5", nil, nil, []byte(`data: {"type":"message_start","message":{"id":"msg_123","model":"claude-fable-5","usage":{"input_tokens":1,"output_tokens":0}}}`), &param)
	for _, event := range [][]byte{
		[]byte(`data: {"type":"content_block_start","index":0,"content_block":{"type":"fallback","from":{"model":"claude-fable-5"},"to":{"model":"claude-opus-4-8"},"trigger":{"type":"refusal"}}}`),
		[]byte(`data: {"type":"content_block_stop","index":0}`),
	} {
		if out := ConvertClaudeResponseToOpenAI(ctx, "claude-fable-5", nil, nil, event, &param); len(out) != 0 {
			t.Fatalf("fallback boundary emitted %d Chat Completions chunks, want 0", len(out))
		}
	}

	text := ConvertClaudeResponseToOpenAI(ctx, "claude-fable-5", nil, nil, []byte(`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Visible."}}`), &param)
	if len(text) != 1 || gjson.GetBytes(text[0], "choices.0.delta.content").String() != "Visible." {
		t.Fatalf("text after fallback boundary was not preserved: %q", text)
	}

	raw := []byte("data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_123\",\"model\":\"claude-fable-5\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"fallback\",\"from\":{\"model\":\"claude-fable-5\"},\"to\":{\"model\":\"claude-opus-4-8\"},\"trigger\":{\"type\":\"refusal\"}}}\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Visible.\"}}\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n")
	nonStream := ConvertClaudeResponseToOpenAINonStream(ctx, "", nil, nil, raw, nil)
	if got := gjson.GetBytes(nonStream, "choices.0.message.content").String(); got != "Visible." {
		t.Fatalf("non-stream text after fallback boundary = %q, want Visible.", got)
	}
}
