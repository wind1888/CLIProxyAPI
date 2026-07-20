package helps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

const (
	testClaudeSessionA = "11111111-1111-4111-8111-111111111111"
	testClaudeSessionB = "22222222-2222-4222-a222-222222222222"
)

func testClaudeSessionPayload(t *testing.T, sessionID string) []byte {
	t.Helper()
	userID, errUserID := BuildClaudeCodeUserIDRequired(strings.Repeat("a", 64), "", sessionID)
	if errUserID != nil {
		t.Fatalf("BuildClaudeCodeUserIDRequired() error = %v", errUserID)
	}
	payload, errPayload := json.Marshal(map[string]any{"metadata": map[string]any{"user_id": userID}})
	if errPayload != nil {
		t.Fatalf("marshal payload: %v", errPayload)
	}
	return payload
}

func TestExtractClaudeCodeSessionIDFromPayloadJSON(t *testing.T) {
	payload := testClaudeSessionPayload(t, testClaudeSessionA)
	got := ExtractClaudeCodeSessionID(context.Background(), payload, nil)
	if got != testClaudeSessionA {
		t.Fatalf("ExtractClaudeCodeSessionID() = %q, want %q", got, testClaudeSessionA)
	}
}

func TestExtractClaudeCodeSessionIDFromHeader(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	ginCtx.Request.Header.Set(ClaudeCodeSessionHeader, "  "+testClaudeSessionA+"  ")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)

	got := ExtractClaudeCodeSessionID(ctx, []byte(`{"model":"gpt-5.4"}`), nil)
	if got != testClaudeSessionA {
		t.Fatalf("ExtractClaudeCodeSessionID() = %q, want %q", got, testClaudeSessionA)
	}
}

func TestClaudeCodePromptCacheStableAcrossRequests(t *testing.T) {
	ctx := context.Background()
	payload := testClaudeSessionPayload(t, testClaudeSessionA)
	first, ok, err := ClaudeCodePromptCache(ctx, "grok-composer-2.5-fast", payload, nil)
	if err != nil {
		t.Fatalf("ClaudeCodePromptCache first error: %v", err)
	}
	if !ok || first.ID == "" {
		t.Fatalf("ClaudeCodePromptCache first = %#v, ok=%v, want cached id", first, ok)
	}
	second, ok, err := ClaudeCodePromptCache(ctx, "grok-composer-2.5-fast", payload, nil)
	if err != nil {
		t.Fatalf("ClaudeCodePromptCache second error: %v", err)
	}
	if !ok || second.ID != first.ID {
		t.Fatalf("second cache id = %q, want %q", second.ID, first.ID)
	}
}

func TestExtractClaudeCodeSessionIDPrefersHeaderOverPayload(t *testing.T) {
	payload := testClaudeSessionPayload(t, testClaudeSessionA)
	headers := http.Header{}
	headers.Set(ClaudeCodeSessionHeader, testClaudeSessionB)

	got := ExtractClaudeCodeSessionID(context.Background(), payload, headers)
	if got != testClaudeSessionB {
		t.Fatalf("ExtractClaudeCodeSessionID() = %q, want %q", got, testClaudeSessionB)
	}
}

func TestResolveClaudeCodeSessionReportsHeaderPayloadConflict(t *testing.T) {
	requested := http.Header{}
	requested.Set(ClaudeCodeSessionHeader, testClaudeSessionB)
	resolution := ResolveClaudeCodeSession(context.Background(), testClaudeSessionPayload(t, testClaudeSessionA), requested)

	if resolution.SessionID != testClaudeSessionB || resolution.Source != ClaudeCodeSessionSourceHeader {
		t.Fatalf("ResolveClaudeCodeSession() selected %#v", resolution)
	}
	if resolution.HeaderSessionID != testClaudeSessionB || resolution.PayloadSessionID != testClaudeSessionA || !resolution.Conflict {
		t.Fatalf("ResolveClaudeCodeSession() conflict = %#v", resolution)
	}
}

func TestResolveClaudeCodeSessionIgnoresInvalidHeaderAndUsesPayload(t *testing.T) {
	headers := http.Header{}
	headers.Set(ClaudeCodeSessionHeader, "not-a-session")
	resolution := ResolveClaudeCodeSession(context.Background(), testClaudeSessionPayload(t, testClaudeSessionA), headers)

	if resolution.SessionID != testClaudeSessionA || resolution.Source != ClaudeCodeSessionSourcePayload || resolution.Conflict {
		t.Fatalf("ResolveClaudeCodeSession() = %#v", resolution)
	}
}

func TestExtractClaudeCodeSessionIDRejectsNonV4AndNonRFCVariant(t *testing.T) {
	for _, sessionID := range []string{
		"11111111-1111-1111-8111-111111111111",
		"11111111-1111-4111-7111-111111111111",
		strings.ToUpper(testClaudeSessionB),
	} {
		headers := http.Header{}
		headers.Set(ClaudeCodeSessionHeader, sessionID)
		if got := ResolveClaudeCodeSession(context.Background(), nil, headers).SessionID; got != "" {
			t.Fatalf("ResolveClaudeCodeSession(%q) = %q, want empty", sessionID, got)
		}
	}
}

func TestExtractClaudeCodeSessionIDFromLegacySuffixRequiresCanonicalUUID(t *testing.T) {
	payload := []byte(`{"metadata":{"user_id":"user_abc_account_def_session_` + testClaudeSessionA + `"}}`)
	if got := ExtractClaudeCodeSessionID(context.Background(), payload, nil); got != testClaudeSessionA {
		t.Fatalf("ExtractClaudeCodeSessionID() = %q, want %q", got, testClaudeSessionA)
	}
	payload = []byte(`{"metadata":{"user_id":"user_abc_account_def_session_not-valid"}}`)
	if got := ExtractClaudeCodeSessionID(context.Background(), payload, nil); got != "" {
		t.Fatalf("ExtractClaudeCodeSessionID(invalid suffix) = %q, want empty", got)
	}
}

func TestClaudeCodeExecutionScopeAcceptsLowercaseHeaderMapKeys(t *testing.T) {
	headers := http.Header{
		"x-claude-code-session-id": []string{testClaudeSessionA},
		"x-claude-code-agent-id":   []string{"lower-agent"},
	}

	scope, ok := ClaudeCodeExecutionScope(context.Background(), nil, headers)
	if !ok || scope != "claude:"+testClaudeSessionA+":agent:lower-agent" {
		t.Fatalf("lowercase header scope = %q, %v", scope, ok)
	}
}

func TestClaudeCodeExecutionScopeIsolatesAgents(t *testing.T) {
	rootHeaders := http.Header{}
	rootHeaders.Set(ClaudeCodeSessionHeader, testClaudeSessionA)
	childAHeaders := rootHeaders.Clone()
	childAHeaders.Set(ClaudeCodeAgentHeader, "agent-a")
	childBHeaders := rootHeaders.Clone()
	childBHeaders.Set(ClaudeCodeAgentHeader, "agent-b")

	rootScope, ok := ClaudeCodeExecutionScope(context.Background(), nil, rootHeaders)
	if !ok || rootScope != "claude:"+testClaudeSessionA+":agent:main" {
		t.Fatalf("root scope = %q, %v", rootScope, ok)
	}
	childAScope, ok := ClaudeCodeExecutionScope(context.Background(), nil, childAHeaders)
	if !ok || childAScope != "claude:"+testClaudeSessionA+":agent:agent-a" {
		t.Fatalf("child A scope = %q, %v", childAScope, ok)
	}
	childBScope, ok := ClaudeCodeExecutionScope(context.Background(), nil, childBHeaders)
	if !ok || childBScope != "claude:"+testClaudeSessionA+":agent:agent-b" {
		t.Fatalf("child B scope = %q, %v", childBScope, ok)
	}
	if rootScope == childAScope || childAScope == childBScope || rootScope == childBScope {
		t.Fatalf("agent scopes are not isolated: root=%q a=%q b=%q", rootScope, childAScope, childBScope)
	}
}

func TestExtractClaudeCodeAgentIDRejectsUnboundedOrControlValues(t *testing.T) {
	for _, agentID := range []string{strings.Repeat("a", 129), "agent\nchild"} {
		headers := http.Header{}
		headers.Set(ClaudeCodeAgentHeader, agentID)
		if got := ExtractClaudeCodeAgentID(context.Background(), headers); got != ClaudeCodeMainAgentID {
			t.Fatalf("ExtractClaudeCodeAgentID(%q) = %q, want %q", agentID, got, ClaudeCodeMainAgentID)
		}
	}
}

func TestClaudeCodePromptCacheDeterministicAndAgentScoped(t *testing.T) {
	rootHeaders := http.Header{}
	rootHeaders.Set(ClaudeCodeSessionHeader, testClaudeSessionA)
	childHeaders := rootHeaders.Clone()
	childHeaders.Set(ClaudeCodeAgentHeader, "agent-a")

	rootFirst, ok, errFirst := ClaudeCodePromptCache(context.Background(), "gpt-5.4", nil, rootHeaders)
	if errFirst != nil || !ok {
		t.Fatalf("root first cache = %#v, %v, %v", rootFirst, ok, errFirst)
	}
	rootSecond, ok, errSecond := ClaudeCodePromptCache(context.Background(), "gpt-5.4", nil, rootHeaders)
	if errSecond != nil || !ok || rootSecond.ID != rootFirst.ID {
		t.Fatalf("root second cache = %#v, %v, %v; want ID %q", rootSecond, ok, errSecond, rootFirst.ID)
	}
	child, ok, errChild := ClaudeCodePromptCache(context.Background(), "gpt-5.4", nil, childHeaders)
	if errChild != nil || !ok || child.ID == rootFirst.ID {
		t.Fatalf("child cache = %#v, %v, %v; root ID %q", child, ok, errChild, rootFirst.ID)
	}
	otherModel, ok, errModel := ClaudeCodePromptCache(context.Background(), "gpt-5.5", nil, rootHeaders)
	if errModel != nil || !ok || otherModel.ID == rootFirst.ID {
		t.Fatalf("other model cache = %#v, %v, %v; root ID %q", otherModel, ok, errModel, rootFirst.ID)
	}
}
