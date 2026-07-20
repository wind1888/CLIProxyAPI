package helps

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

const (
	ClaudeCodeSessionHeader = "X-Claude-Code-Session-Id"
	ClaudeCodeAgentHeader   = "X-Claude-Code-Agent-Id"
	ClaudeCodeMainAgentID   = "main"
)

const claudeCodeSessionSuffix = "_session_"

// ClaudeCodeSessionSource identifies the source selected for a canonical session ID.
type ClaudeCodeSessionSource string

const (
	ClaudeCodeSessionSourceNone    ClaudeCodeSessionSource = ""
	ClaudeCodeSessionSourceHeader  ClaudeCodeSessionSource = "header"
	ClaudeCodeSessionSourcePayload ClaudeCodeSessionSource = "payload"
)

// ClaudeCodeSessionResolution contains the valid session candidates and the
// deterministic header-first selection used by Claude Code execution state.
type ClaudeCodeSessionResolution struct {
	SessionID        string
	HeaderSessionID  string
	PayloadSessionID string
	Source           ClaudeCodeSessionSource
	Conflict         bool
	InvalidHeader    bool
	InvalidPayload   bool
}

// ExtractClaudeCodeSessionID resolves a Claude Code session ID, preferring X-Claude-Code-Session-Id over payload metadata.
// It preserves bounded legacy identifiers for existing execution-state callers;
// new request-shaping paths should use ResolveClaudeCodeSession for UUIDv4-only parsing.
func ExtractClaudeCodeSessionID(ctx context.Context, payload []byte, headers http.Header) string {
	if sessionID := claudeCodeHeader(ctx, headers, ClaudeCodeSessionHeader); isValidLegacyClaudeCodeSessionID(sessionID) {
		return strings.TrimSpace(sessionID)
	}
	return extractLegacyClaudeCodeSessionIDFromPayload(payload)
}

// ResolveClaudeCodeSession parses canonical UUIDv4 session IDs from headers and
// payload metadata. A valid header wins for compatibility; Conflict reports a
// disagreement between valid header and payload candidates.
func ResolveClaudeCodeSession(ctx context.Context, payload []byte, headers http.Header) ClaudeCodeSessionResolution {
	headerSessionID, headerConflict, invalidHeader := resolveClaudeCodeSessionIDFromHeaders(ctx, headers)
	payloadSessionID := extractClaudeCodeSessionIDFromPayload(payload)
	invalidPayload := hasInvalidClaudeCodeSessionPayload(payload, payloadSessionID)
	resolution := ClaudeCodeSessionResolution{
		HeaderSessionID:  headerSessionID,
		PayloadSessionID: payloadSessionID,
		Conflict:         headerConflict || (headerSessionID != "" && payloadSessionID != "" && headerSessionID != payloadSessionID),
		InvalidHeader:    invalidHeader,
		InvalidPayload:   invalidPayload,
	}
	if headerSessionID != "" {
		resolution.SessionID = headerSessionID
		resolution.Source = ClaudeCodeSessionSourceHeader
		return resolution
	}
	if payloadSessionID != "" {
		resolution.SessionID = payloadSessionID
		resolution.Source = ClaudeCodeSessionSourcePayload
	}
	return resolution
}

// ExtractClaudeCodeAgentID resolves the Claude Code agent ID and uses a stable sentinel for the root agent.
func ExtractClaudeCodeAgentID(ctx context.Context, headers http.Header) string {
	if agentID := strings.TrimSpace(claudeCodeHeader(ctx, headers, ClaudeCodeAgentHeader)); isValidClaudeCodeAgentID(agentID) {
		return agentID
	}
	return ClaudeCodeMainAgentID
}

// ClaudeCodeExecutionScope returns the stable root-session and agent identity used by Codex execution state.
func ClaudeCodeExecutionScope(ctx context.Context, payload []byte, headers http.Header) (string, bool) {
	sessionID := ExtractClaudeCodeSessionID(ctx, payload, headers)
	if sessionID == "" {
		return "", false
	}
	return "claude:" + sessionID + ":agent:" + ExtractClaudeCodeAgentID(ctx, headers), true
}

func claudeCodeHeader(ctx context.Context, headers http.Header, name string) string {
	if value := headerValueCaseInsensitive(headers, name); value != "" {
		return value
	}
	if ctx != nil {
		if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
			return headerValueCaseInsensitive(ginCtx.Request.Header, name)
		}
	}
	return ""
}

func resolveClaudeCodeSessionIDFromHeaders(ctx context.Context, headers http.Header) (string, bool, bool) {
	values := headerValuesCaseInsensitive(headers, ClaudeCodeSessionHeader)
	if len(values) == 0 && ctx != nil {
		if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
			values = headerValuesCaseInsensitive(ginCtx.Request.Header, ClaudeCodeSessionHeader)
		}
	}
	selected := ""
	distinct := make(map[string]struct{})
	invalid := false
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !isValidClaudeCodeUUID(value) {
			invalid = true
			continue
		}
		if selected == "" {
			selected = value
		}
		distinct[value] = struct{}{}
	}
	return selected, len(distinct) > 1, invalid
}

func headerValueCaseInsensitive(headers http.Header, name string) string {
	for _, value := range headerValuesCaseInsensitive(headers, name) {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func headerValuesCaseInsensitive(headers http.Header, name string) []string {
	if headers == nil {
		return nil
	}
	canonicalName := http.CanonicalHeaderKey(name)
	keys := make([]string, 0, 1)
	for key := range headers {
		if key != canonicalName && strings.EqualFold(key, name) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if _, ok := headers[canonicalName]; ok {
		keys = append([]string{canonicalName}, keys...)
	}
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, headers[key]...)
	}
	return values
}

func extractClaudeCodeSessionIDFromPayload(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	userID := gjson.GetBytes(payload, "metadata.user_id").String()
	userID = strings.TrimSpace(userID)
	if userID == "" || len(userID) > maxClaudeCodeUserIDLength {
		return ""
	}
	if parsed, errParse := ParseClaudeCodeClientUserID(userID); errParse == nil {
		return parsed.SessionID
	}
	if suffixIndex := strings.LastIndex(userID, claudeCodeSessionSuffix); suffixIndex >= 0 {
		sessionID := strings.TrimSpace(userID[suffixIndex+len(claudeCodeSessionSuffix):])
		if isValidClaudeCodeUUID(sessionID) {
			return sessionID
		}
	}
	return ""
}

func hasInvalidClaudeCodeSessionPayload(payload []byte, sessionID string) bool {
	if sessionID != "" || len(payload) == 0 {
		return false
	}
	userID := gjson.GetBytes(payload, "metadata.user_id")
	return userID.Exists() && strings.TrimSpace(userID.String()) != ""
}

func extractLegacyClaudeCodeSessionIDFromPayload(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	userID := strings.TrimSpace(gjson.GetBytes(payload, "metadata.user_id").String())
	if userID == "" || len(userID) > maxClaudeCodeUserIDLength {
		return ""
	}
	if parsed, errParse := ParseClaudeCodeClientUserID(userID); errParse == nil {
		return parsed.SessionID
	}
	if strings.HasPrefix(userID, "{") {
		sessionID := strings.TrimSpace(gjson.Get(userID, "session_id").String())
		if isValidLegacyClaudeCodeSessionID(sessionID) {
			return sessionID
		}
	}
	if suffixIndex := strings.LastIndex(userID, claudeCodeSessionSuffix); suffixIndex >= 0 {
		sessionID := strings.TrimSpace(userID[suffixIndex+len(claudeCodeSessionSuffix):])
		if isValidLegacyClaudeCodeSessionSuffix(sessionID) {
			return sessionID
		}
	}
	return ""
}

func isValidLegacyClaudeCodeSessionSuffix(sessionID string) bool {
	if !isValidLegacyClaudeCodeSessionID(sessionID) {
		return false
	}
	for _, character := range sessionID {
		if (character < 'a' || character > 'f') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func isValidLegacyClaudeCodeSessionID(sessionID string) bool {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || len(sessionID) > 128 {
		return false
	}
	for _, character := range sessionID {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func isValidClaudeCodeAgentID(agentID string) bool {
	if agentID == "" || len(agentID) > 128 {
		return false
	}
	for _, character := range agentID {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

// ClaudeCodePromptCache derives a deterministic upstream prompt_cache_key for one Claude Code agent.
func ClaudeCodePromptCache(ctx context.Context, modelName string, payload []byte, headers http.Header) (CodexCache, bool, error) {
	modelName = strings.TrimSpace(modelName)
	executionScope, ok := ClaudeCodeExecutionScope(ctx, payload, headers)
	if modelName == "" || !ok {
		return CodexCache{}, false, nil
	}
	identity := strings.Join([]string{"cli-proxy-api:codex:claude-code", modelName, executionScope}, "\x00")
	return CodexCache{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(identity)).String()}, true, nil
}
