package executor

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	sigcompat "github.com/router-for-me/CLIProxyAPI/v7/internal/signature"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/gin-gonic/gin"
)

// ClaudeExecutor is a stateless executor for Anthropic Claude over the messages API.
// If api_key is unavailable on auth, it falls back to legacy via ClientAdapter.
type ClaudeExecutor struct {
	cfg                     *config.Config
	requestLogProvider      string
	upstreamModelNormalizer func(string) string
}

type claudeCloakDecisionContextKey struct{}

func withClaudeCloakDecision(ctx context.Context, enabled bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, claudeCloakDecisionContextKey{}, enabled)
}

func claudeCloakDecisionFromContext(ctx context.Context) (bool, bool) {
	if ctx == nil {
		return false, false
	}
	enabled, exists := ctx.Value(claudeCloakDecisionContextKey{}).(bool)
	return enabled, exists
}

// claudeToolPrefix is empty to match real Claude Code behavior (no tool name prefix).
// Previously "proxy_" was used but this is a detectable fingerprint difference.
const claudeToolPrefix = ""

const (
	claudePrevRequestHeader       = "X-CPA-Claude-Prev-Request-Id"
	claudeSyntheticSubagentHeader = "X-CPA-Claude-Is-Subagent"
	claudePreviousRequestTTL      = 6 * time.Hour
	claudePreviousRequestMax      = 4096
)

type claudePreviousRequestEntry struct {
	requestID string
	expiresAt time.Time
}

var (
	claudePreviousRequestsMu sync.Mutex
	claudePreviousRequests   = make(map[string]claudePreviousRequestEntry)
)

func shouldSanitizeClaudeMessagesForUpstream(baseModel string) bool {
	return sigcompat.SignatureProviderFromModelName(baseModel) == sigcompat.SignatureProviderClaude
}

func sanitizeClaudeMessagesForClaudeUpstreamWithDebug(ctx context.Context, body []byte, baseModel string) []byte {
	sanitized := body
	if shouldSanitizeClaudeMessagesForUpstream(baseModel) {
		var report sigcompat.SignatureSanitizeReport
		sanitized, report = sigcompat.SanitizeClaudeMessagesForClaudeUpstream(body, baseModel)
		logClaudeSignatureSanitizeReport(ctx, baseModel, report)
	}
	return sanitizeClaudeWebSearchDomains(sanitized)
}

// sanitizeClaudeWebSearchDomains removes empty allowed_domains/blocked_domains
// arrays from built-in web_search tools. Some clients (e.g. litellm) emit an
// empty array instead of omitting the field, and Anthropic rejects it with
// "Empty list of domains is ambiguous. Provide at least one domain or null.".
// Deleting the key is equivalent to leaving it unset.
func sanitizeClaudeWebSearchDomains(body []byte) []byte {
	tools := gjson.GetBytes(body, "tools")
	if !tools.Exists() || !tools.IsArray() {
		return body
	}
	tools.ForEach(func(index, tool gjson.Result) bool {
		if !strings.HasPrefix(tool.Get("type").String(), "web_search_") {
			return true
		}
		for _, field := range []string{"allowed_domains", "blocked_domains"} {
			value := tool.Get(field)
			if value.Exists() && value.IsArray() && len(value.Array()) == 0 {
				path := fmt.Sprintf("tools.%d.%s", index.Int(), field)
				if updated, errDelete := sjson.DeleteBytes(body, path); errDelete == nil {
					body = updated
				}
			}
		}
		return true
	})
	return body
}

func logClaudeSignatureSanitizeReport(ctx context.Context, baseModel string, report sigcompat.SignatureSanitizeReport) {
	if report.DroppedBlocks == 0 && report.DroppedSignatures == 0 && report.ReplacedSignatures == 0 {
		return
	}

	fields := log.Fields{
		"component":           "signature_sanitizer",
		"executor":            "claude",
		"action":              "sanitize_claude_messages",
		"target_provider":     string(report.TargetProvider),
		"target_model":        baseModel,
		"preserved":           report.Preserved,
		"dropped_blocks":      report.DroppedBlocks,
		"dropped_signatures":  report.DroppedSignatures,
		"replaced_signatures": report.ReplacedSignatures,
	}
	if len(report.Decisions) > 0 {
		decision := report.Decisions[0]
		fields["first_block_kind"] = string(decision.BlockKind)
		fields["first_detected_provider"] = string(decision.DetectedProvider)
		fields["first_reason"] = decision.Reason
	}

	helps.LogWithRequestID(ctx).WithFields(fields).Debug("claude executor: sanitized signature history before upstream")
}

// oauthToolRenameMap maps compatible lowercase tool aliases to the names used by
// Claude Code 2.1.216. Aliases without a schema-compatible official tool remain
// unchanged rather than being disguised as a different tool.
var oauthToolRenameMap = map[string]string{
	"bash":         "Bash",
	"read":         "Read",
	"write":        "Write",
	"edit":         "Edit",
	"glob":         "Glob",
	"grep":         "Grep",
	"task":         "Agent",
	"webfetch":     "WebFetch",
	"websearch":    "WebSearch",
	"todowrite":    "TodoWrite",
	"question":     "AskUserQuestion",
	"skill":        "Skill",
	"todoread":     "TaskList",
	"notebookedit": "NotebookEdit",
	"taskcreate":   "TaskCreate",
	"toolsearch":   "ToolSearch",
	"tool_search":  "ToolSearch",
}

// The reverse map is now computed per-request in remapOAuthToolNames so that
// only names the client actually caused us to rewrite are restored on the
// response. A global reverse map — as used previously — corrupted responses
// for clients that sent mixed casing (e.g. `Bash` TitleCase alongside `glob`
// lowercase; the request flagged renames via `glob` -> `Glob`, then the global
// reverse map incorrectly rewrote every `Bash` in the response to `bash`).

// oauthToolsToRemove lists tool names that must be stripped from OAuth requests
// even after remapping. Currently empty — all tools are mapped instead of removed.
var oauthToolsToRemove = map[string]bool{}

// Anthropic-compatible upstreams may reject or even crash when Claude models
// omit max_tokens. Prefer registered model metadata before using a fallback.
const defaultModelMaxTokens = 1024

func NewClaudeExecutor(cfg *config.Config) *ClaudeExecutor {
	return &ClaudeExecutor{cfg: cfg, upstreamModelNormalizer: normalizeClaudeUpstreamModel}
}

func (e *ClaudeExecutor) Identifier() string { return "claude" }

func (e *ClaudeExecutor) upstreamRequestLogProvider() string {
	if provider := strings.TrimSpace(e.requestLogProvider); provider != "" {
		return provider
	}
	return e.Identifier()
}

func (e *ClaudeExecutor) upstreamModel(baseModel string) string {
	if e.upstreamModelNormalizer != nil {
		return e.upstreamModelNormalizer(baseModel)
	}
	return baseModel
}

func normalizeClaudeUpstreamModel(model string) string {
	trimmed := strings.TrimSpace(model)
	if trimmed == "" {
		return model
	}
	suffix := ""
	base := trimmed
	if parsed := thinking.ParseSuffix(trimmed); parsed.HasSuffix {
		base = strings.TrimSpace(parsed.ModelName)
		suffix = "(" + parsed.RawSuffix + ")"
	}
	if strings.HasSuffix(strings.ToLower(base), "[1m]") {
		base = strings.TrimSpace(base[:len(base)-len("[1m]")])
	}
	if base == "" {
		return trimmed
	}
	return base + suffix
}

func setClaudeRequestModel(body []byte, model string) []byte {
	current := gjson.GetBytes(body, "model")
	if current.Type == gjson.String && current.String() == model {
		return body
	}
	updated, errSet := sjson.SetBytes(body, "model", model)
	if errSet != nil {
		return body
	}
	return updated
}

func (e *ClaudeExecutor) restoreResponseModel(payload []byte, model string) []byte {
	model = strings.TrimSpace(model)
	if e.upstreamModelNormalizer == nil || model == "" || e.upstreamModelNormalizer(model) == model {
		return payload
	}
	return restoreClaudeResponseModel(payload, model)
}

func restoreClaudeResponseModel(payload []byte, model string) []byte {
	if updated, changed := setClaudeResponseModel(payload, model); changed {
		return updated
	}

	trimmed := bytes.TrimSpace(payload)
	if !bytes.HasPrefix(trimmed, []byte("data:")) {
		return payload
	}
	dataIndex := bytes.Index(payload, []byte("data:"))
	if dataIndex < 0 {
		return payload
	}
	rawJSON := bytes.TrimSpace(payload[dataIndex+len("data:"):])
	updated, changed := setClaudeResponseModel(rawJSON, model)
	if !changed {
		return payload
	}
	rebuilt := make([]byte, 0, dataIndex+len("data: ")+len(updated))
	rebuilt = append(rebuilt, payload[:dataIndex]...)
	rebuilt = append(rebuilt, []byte("data: ")...)
	rebuilt = append(rebuilt, updated...)
	return rebuilt
}

func setClaudeResponseModel(payload []byte, model string) ([]byte, bool) {
	if !gjson.ValidBytes(payload) {
		return payload, false
	}
	updated := payload
	changed := false
	for _, path := range []string{"model", "message.model"} {
		if !gjson.GetBytes(updated, path).Exists() {
			continue
		}
		next, errSet := sjson.SetBytes(updated, path, model)
		if errSet != nil {
			continue
		}
		updated = next
		changed = true
	}
	return updated, changed
}

// PrepareRequest injects Claude credentials into the outgoing HTTP request.
func (e *ClaudeExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	apiKey, _ := claudeCreds(auth)
	if strings.TrimSpace(apiKey) == "" {
		return nil
	}
	useAPIKey := auth != nil && auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != ""
	isAnthropicBase := helps.IsClaudeFirstPartyAPIURL(req.URL)
	if isAnthropicBase && useAPIKey {
		req.Header.Del("Authorization")
		req.Header.Set("x-api-key", apiKey)
	} else {
		req.Header.Del("x-api-key")
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(req, attrs)
	return nil
}

// HttpRequest injects Claude credentials into the request and executes it.
func (e *ClaudeExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("claude executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

func (e *ClaudeExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	ctx, opts.Headers = resolveClaudeClientContext(ctx, opts.Headers)
	if opts.Alt == "responses/compact" {
		return resp, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	upstreamModel := e.upstreamModel(baseModel)

	apiKey, baseURL := claudeCreds(auth)
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)
	from := opts.SourceFormat
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	to := sdktranslator.FromString("claude")
	// Use streaming translation to preserve function calling, except for Claude.
	// A synthetic Claude Code SDK request may still be sent upstream as a stream;
	// that decision is made after cloaking/auth classification below and its SSE is
	// accumulated back into a normal Message before returning from Execute.
	translationStream := from != to
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, translationStream)
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, translationStream)
	body = setClaudeRequestModel(body, upstreamModel)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return resp, err
	}
	if rebuildMidSystemMessageEnabled(e.cfg, auth) {
		body = rebuildMidSystemMessagesToTopLevel(body)
	}
	// Payload rules are proxy-side inputs. Apply them before deriving the session,
	// customer-system envelope, tool-conditioned prompt, metadata.user_id, and CCH
	// so those values always describe the body that is actually sent upstream.
	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, requestedModel, requestPath, opts.Headers)
	effectiveModel := strings.TrimSpace(gjson.GetBytes(body, "model").String())
	if effectiveModel == "" {
		effectiveModel = baseModel
	}
	canonicalSessionID, errSessionID := resolveClaudeCanonicalSessionIDRequired(ctx, body, originalPayload, opts.Headers, opts.Metadata, req.Metadata)
	if errSessionID != nil {
		return resp, errSessionID
	}
	if errIdentity := validateClaudeClientOAuthAccount(ctx, auth, apiKey, baseURL, body, originalPayload); errIdentity != nil {
		return resp, errIdentity
	}
	ctx, err = withClaudeCanonicalSessionIDRequired(ctx, canonicalSessionID)
	if err != nil {
		return resp, err
	}

	// Apply cloaking (system prompt injection, fake user ID, sensitive word obfuscation)
	// based on client type and configuration.
	body, err = applyCloaking(ctx, e.cfg, auth, body, effectiveModel, apiKey)
	if err != nil {
		return resp, err
	}

	cloakRequest := shouldApplyClaudeCloaking(ctx, e.cfg, auth)
	ctx = withClaudeCloakDecision(ctx, cloakRequest)
	oauthToken := isClaudeOAuthAuth(auth, apiKey)
	firstPartyClaude := isClaudeFirstPartyBaseURL(baseURL)
	firstPartyOAuth := oauthToken && firstPartyClaude
	syntheticFirstPartyClaude := cloakRequest && firstPartyClaude && !helps.IsClaudeCodeClientUserAgent(getClientUserAgent(ctx))
	if syntheticFirstPartyClaude {
		body = ensureClaudeCodeMaxTokens(body, effectiveModel)
	} else {
		body = ensureModelMaxTokens(body, effectiveModel)
	}
	syntheticFirstPartyOAuthStream := syntheticFirstPartyClaude && oauthToken
	previousRequestScope := claudePreviousRequestScope(ctx, auth)
	upstreamStream := translationStream || syntheticFirstPartyOAuthStream
	if cloakRequest {
		body = prepareClaudeCloakedThinking(body, effectiveModel, firstPartyOAuth)
		if firstPartyClaude {
			body = ensureClaudeCodeContextManagement(body)
			body = ensureClaudeCodeToolsArray(body)
		}
		cacheTTL := ""
		if firstPartyOAuth {
			cacheTTL = helps.OfficialClaudeCodeOAuthProfile().CacheTTL
		}
		body = ensureClaudeCodeCurrentUserCacheControlWithTTL(body, cacheTTL)
		body = removeTopLevelCacheControlWhenExplicit(body)
		if countCacheControls(body) == 0 {
			body = ensureCacheControl(body)
		}
		body = enforceCacheControlLimit(body, 4)
		if firstPartyOAuth {
			body = normalizeClaudeOAuthCacheControlTTL(body)
		}
		body = normalizeCacheControlTTL(body)
	}
	if syntheticFirstPartyOAuthStream {
		body = ensureSyntheticClaudeCodeFallbacks(body, effectiveModel)
	}

	// Extract betas from body and convert to header
	var extraBetas []string
	extraBetas, body = extractAndRemoveBetas(body)
	if syntheticFirstPartyOAuthStream {
		extraBetas = appendSyntheticClaudeCodeConditionalBetas(extraBetas, body, effectiveModel, true)
	}
	bodyForTranslation := body
	bodyForUpstream := body
	var oauthToolNamesReverseMap map[string]string
	if cloakRequest && firstPartyOAuth {
		bodyForUpstream, oauthToolNamesReverseMap = prepareClaudeOAuthToolNamesForUpstream(bodyForUpstream, claudeToolPrefix, auth.ToolPrefixDisabled())
	}
	bodyForUpstream = sanitizeClaudeMessagesForClaudeUpstreamWithDebug(ctx, bodyForUpstream, effectiveModel)
	if syntheticFirstPartyOAuthStream {
		bodyForUpstream, _ = sjson.SetBytes(bodyForUpstream, "stream", true)
		bodyForUpstream = applySyntheticClaudeBillingAttribution(ctx, bodyForUpstream, previousRequestScope)
		bodyForUpstream = canonicalizeSyntheticClaudeCodeBodyOrder(bodyForUpstream)
	}
	// Sign CPA-generated cloak payloads and refresh a supported native client's
	// CCH after any configured proxy-side request transformation.
	if cloakRequest && claudeCCHSigningEnabled(e.cfg, firstPartyOAuth, baseURL) {
		bodyForUpstream, err = signAnthropicMessagesBody(bodyForUpstream)
		if err != nil {
			return resp, fmt.Errorf("sign Claude request cch: %w", err)
		}
	} else if firstPartyOAuth && helps.IsClaudeCodeClientUserAgent(getClientUserAgent(ctx)) {
		bodyForUpstream, err = resignAnthropicMessagesBody(bodyForUpstream)
		if err != nil {
			return resp, fmt.Errorf("re-sign Claude Code request cch: %w", err)
		}
	}
	reporter.SetTranslatedReasoningEffort(bodyForUpstream, to.String())

	url := fmt.Sprintf("%s/v1/messages?beta=true", baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyForUpstream))
	if err != nil {
		return resp, err
	}
	if errHeaders := applyClaudeHeadersForBodyAndModel(httpReq, auth, apiKey, upstreamStream, extraBetas, e.cfg, opts.Headers, bodyForUpstream, requestedModel); errHeaders != nil {
		return resp, errHeaders
	}
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      bodyForUpstream,
		Provider:  e.upstreamRequestLogProvider(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		// Decompress error responses — pass the Content-Encoding value (may be empty)
		// and let decodeResponseBody handle both header-declared and magic-byte-detected
		// compression.  This keeps error-path behaviour consistent with the success path.
		errBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, decErr)
			msg := fmt.Sprintf("failed to decode error response body: %v", decErr)
			helps.LogWithRequestID(ctx).Warn(msg)
			return resp, statusErr{code: httpResp.StatusCode, msg: msg}
		}
		b, readErr := io.ReadAll(errBody)
		if readErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, readErr)
			msg := fmt.Sprintf("failed to read error response body: %v", readErr)
			helps.LogWithRequestID(ctx).Warn(msg)
			b = []byte(msg)
		}
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		if errClose := errBody.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return resp, err
	}
	decodedBody, err := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return resp, err
	}
	defer func() {
		if errClose := decodedBody.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
	}()
	data, err := io.ReadAll(decodedBody)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, data)
	if upstreamStream && !syntheticFirstPartyOAuthStream {
		if errValidate := validateClaudeStreamingResponse(data); errValidate != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errValidate)
			return resp, errValidate
		}
		lines := bytes.Split(data, []byte("\n"))
		for _, line := range lines {
			if detail, ok := helps.ParseClaudeStreamUsage(line); ok {
				reporter.Publish(ctx, detail)
			}
		}
	} else if !syntheticFirstPartyOAuthStream {
		reporter.Publish(ctx, helps.ParseClaudeUsage(data))
	}
	if syntheticFirstPartyOAuthStream {
		aggregated, restoredStream, errAggregate := aggregateClaudeMessageStream(data, func(line []byte) []byte {
			line = restoreClaudeOAuthToolNamesFromStreamLine(line, claudeToolPrefix, auth.ToolPrefixDisabled(), oauthToolNamesReverseMap)
			return e.restoreResponseModel(line, req.Model)
		})
		if errAggregate != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errAggregate)
			return resp, errAggregate
		}
		storeClaudePreviousRequest(previousRequestScope, httpResp.Header.Get("request-id"))
		reporter.Publish(ctx, helps.ParseClaudeUsage(aggregated))
		if responseFormat == to {
			data = aggregated
		} else {
			// Existing non-Claude translators consume Anthropic SSE. They receive
			// the already restored and strictly validated stream.
			data = restoredStream
		}
	} else {
		data = restoreClaudeOAuthToolNamesFromResponse(data, claudeToolPrefix, auth.ToolPrefixDisabled(), oauthToolNamesReverseMap)
		data = e.restoreResponseModel(data, req.Model)
	}
	var param any
	out := sdktranslator.TranslateNonStream(
		ctx,
		to,
		responseFormat,
		req.Model,
		opts.OriginalRequest,
		bodyForTranslation,
		data,
		&param,
	)
	responseHeaders := httpResp.Header.Clone()
	if syntheticFirstPartyOAuthStream && responseFormat == to {
		responseHeaders.Set("Content-Type", "application/json")
		responseHeaders.Del("Content-Length")
	}
	resp = cliproxyexecutor.Response{Payload: out, Headers: responseHeaders}
	return resp, nil
}

func (e *ClaudeExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	ctx, opts.Headers = resolveClaudeClientContext(ctx, opts.Headers)
	if opts.Alt == "responses/compact" {
		return nil, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	upstreamModel := e.upstreamModel(baseModel)

	apiKey, baseURL := claudeCreds(auth)
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)
	from := opts.SourceFormat
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	to := sdktranslator.FromString("claude")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, true)
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, true)
	body = setClaudeRequestModel(body, upstreamModel)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, err
	}
	if rebuildMidSystemMessageEnabled(e.cfg, auth) {
		body = rebuildMidSystemMessagesToTopLevel(body)
	}
	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, requestedModel, requestPath, opts.Headers)
	effectiveModel := strings.TrimSpace(gjson.GetBytes(body, "model").String())
	if effectiveModel == "" {
		effectiveModel = baseModel
	}
	canonicalSessionID, errSessionID := resolveClaudeCanonicalSessionIDRequired(ctx, body, originalPayload, opts.Headers, opts.Metadata, req.Metadata)
	if errSessionID != nil {
		return nil, errSessionID
	}
	if errIdentity := validateClaudeClientOAuthAccount(ctx, auth, apiKey, baseURL, body, originalPayload); errIdentity != nil {
		return nil, errIdentity
	}
	ctx, err = withClaudeCanonicalSessionIDRequired(ctx, canonicalSessionID)
	if err != nil {
		return nil, err
	}

	// Apply cloaking (system prompt injection, fake user ID, sensitive word obfuscation)
	// based on client type and configuration.
	body, err = applyCloaking(ctx, e.cfg, auth, body, effectiveModel, apiKey)
	if err != nil {
		return nil, err
	}

	cloakRequest := shouldApplyClaudeCloaking(ctx, e.cfg, auth)
	ctx = withClaudeCloakDecision(ctx, cloakRequest)
	oauthToken := isClaudeOAuthAuth(auth, apiKey)
	firstPartyClaude := isClaudeFirstPartyBaseURL(baseURL)
	firstPartyOAuth := oauthToken && firstPartyClaude
	syntheticFirstPartyClaude := cloakRequest && firstPartyClaude && !helps.IsClaudeCodeClientUserAgent(getClientUserAgent(ctx))
	if syntheticFirstPartyClaude {
		body = ensureClaudeCodeMaxTokens(body, effectiveModel)
	} else {
		body = ensureModelMaxTokens(body, effectiveModel)
	}
	syntheticFirstPartyOAuth := syntheticFirstPartyClaude && oauthToken
	previousRequestScope := claudePreviousRequestScope(ctx, auth)
	if cloakRequest {
		body = prepareClaudeCloakedThinking(body, effectiveModel, firstPartyOAuth)
		if firstPartyClaude {
			body = ensureClaudeCodeContextManagement(body)
			body = ensureClaudeCodeToolsArray(body)
		}
		cacheTTL := ""
		if firstPartyOAuth {
			cacheTTL = helps.OfficialClaudeCodeOAuthProfile().CacheTTL
		}
		body = ensureClaudeCodeCurrentUserCacheControlWithTTL(body, cacheTTL)
		body = removeTopLevelCacheControlWhenExplicit(body)
		if countCacheControls(body) == 0 {
			body = ensureCacheControl(body)
		}
		body = enforceCacheControlLimit(body, 4)
		if firstPartyOAuth {
			body = normalizeClaudeOAuthCacheControlTTL(body)
		}
		body = normalizeCacheControlTTL(body)
	}
	if syntheticFirstPartyOAuth {
		body = ensureSyntheticClaudeCodeFallbacks(body, effectiveModel)
	}

	// Extract betas from body and convert to header
	var extraBetas []string
	extraBetas, body = extractAndRemoveBetas(body)
	if syntheticFirstPartyOAuth {
		extraBetas = appendSyntheticClaudeCodeConditionalBetas(extraBetas, body, effectiveModel, true)
	}
	bodyForTranslation := body
	bodyForUpstream := body
	var oauthToolNamesReverseMap map[string]string
	if cloakRequest && firstPartyOAuth {
		bodyForUpstream, oauthToolNamesReverseMap = prepareClaudeOAuthToolNamesForUpstream(bodyForUpstream, claudeToolPrefix, auth.ToolPrefixDisabled())
	}
	bodyForUpstream = sanitizeClaudeMessagesForClaudeUpstreamWithDebug(ctx, bodyForUpstream, effectiveModel)
	// ExecuteStream always uses Anthropic's streaming wire protocol. Set this on
	// the final upstream body so payload overrides cannot accidentally disable it.
	bodyForUpstream, _ = sjson.SetBytes(bodyForUpstream, "stream", true)
	if syntheticFirstPartyOAuth {
		bodyForUpstream = applySyntheticClaudeBillingAttribution(ctx, bodyForUpstream, previousRequestScope)
		bodyForUpstream = canonicalizeSyntheticClaudeCodeBodyOrder(bodyForUpstream)
	}
	// Sign CPA-generated cloak payloads and refresh a supported native client's
	// CCH after any configured proxy-side request transformation.
	if cloakRequest && claudeCCHSigningEnabled(e.cfg, firstPartyOAuth, baseURL) {
		bodyForUpstream, err = signAnthropicMessagesBody(bodyForUpstream)
		if err != nil {
			return nil, fmt.Errorf("sign Claude streaming request cch: %w", err)
		}
	} else if firstPartyOAuth && helps.IsClaudeCodeClientUserAgent(getClientUserAgent(ctx)) {
		bodyForUpstream, err = resignAnthropicMessagesBody(bodyForUpstream)
		if err != nil {
			return nil, fmt.Errorf("re-sign Claude Code streaming request cch: %w", err)
		}
	}
	reporter.SetTranslatedReasoningEffort(bodyForUpstream, to.String())

	url := fmt.Sprintf("%s/v1/messages?beta=true", baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyForUpstream))
	if err != nil {
		return nil, err
	}
	if errHeaders := applyClaudeHeadersForBodyAndModel(httpReq, auth, apiKey, true, extraBetas, e.cfg, opts.Headers, bodyForUpstream, requestedModel); errHeaders != nil {
		return nil, errHeaders
	}
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      bodyForUpstream,
		Provider:  e.upstreamRequestLogProvider(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		// Decompress error responses — pass the Content-Encoding value (may be empty)
		// and let decodeResponseBody handle both header-declared and magic-byte-detected
		// compression.  This keeps error-path behaviour consistent with the success path.
		errBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, decErr)
			msg := fmt.Sprintf("failed to decode error response body: %v", decErr)
			helps.LogWithRequestID(ctx).Warn(msg)
			return nil, statusErr{code: httpResp.StatusCode, msg: msg}
		}
		b, readErr := io.ReadAll(errBody)
		if readErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, readErr)
			msg := fmt.Sprintf("failed to read error response body: %v", readErr)
			helps.LogWithRequestID(ctx).Warn(msg)
			b = []byte(msg)
		}
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		if errClose := errBody.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return nil, err
	}
	decodedBody, err := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return nil, err
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := decodedBody.Close(); errClose != nil {
				log.Errorf("response body close error: %v", errClose)
			}
		}()

		// If the response target is Claude, directly forward complete SSE events without translation.
		if responseFormat == to {
			scanner := bufio.NewScanner(decodedBody)
			scanner.Buffer(nil, 52_428_800) // 50MB
			var event bytes.Buffer
			hasMessageStop := false
			flushEvent := func() bool {
				if event.Len() == 0 {
					return true
				}
				cloned := bytes.Clone(event.Bytes())
				event.Reset()
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: cloned}:
					return true
				case <-ctx.Done():
					return false
				}
			}
			for scanner.Scan() {
				line := scanner.Bytes()
				helps.AppendAPIResponseChunk(ctx, e.cfg, line)
				if detail, ok := helps.ParseClaudeStreamUsage(line); ok {
					reporter.Publish(ctx, detail)
				}
				if payload := helps.JSONPayload(line); len(payload) > 0 && gjson.GetBytes(payload, "type").String() == "message_stop" {
					hasMessageStop = true
				}
				line = restoreClaudeOAuthToolNamesFromStreamLine(line, claudeToolPrefix, auth.ToolPrefixDisabled(), oauthToolNamesReverseMap)
				line = e.restoreResponseModel(line, req.Model)
				event.Write(line)
				event.WriteByte('\n')
				if len(bytes.TrimSpace(line)) == 0 && !flushEvent() {
					return
				}
			}
			if !flushEvent() {
				return
			}
			if errScan := scanner.Err(); errScan != nil {
				helps.RecordAPIResponseError(ctx, e.cfg, errScan)
				reporter.PublishFailure(ctx, errScan)
				select {
				case out <- cliproxyexecutor.StreamChunk{Err: errScan}:
				case <-ctx.Done():
				}
				return
			}
			if !hasMessageStop {
				errMissingStop := claudeStreamProtocolErrorf("stream response ended before message_stop")
				helps.RecordAPIResponseError(ctx, e.cfg, errMissingStop)
				reporter.PublishFailure(ctx, errMissingStop)
				select {
				case out <- cliproxyexecutor.StreamChunk{Err: errMissingStop}:
				case <-ctx.Done():
				}
			} else if syntheticFirstPartyOAuth {
				storeClaudePreviousRequest(previousRequestScope, httpResp.Header.Get("request-id"))
			}
			return
		}

		// For other formats, use translation
		scanner := bufio.NewScanner(decodedBody)
		scanner.Buffer(nil, 52_428_800) // 50MB
		var param any
		hasMessageStop := false
		for scanner.Scan() {
			line := scanner.Bytes()
			helps.AppendAPIResponseChunk(ctx, e.cfg, line)
			if detail, ok := helps.ParseClaudeStreamUsage(line); ok {
				reporter.Publish(ctx, detail)
			}
			if payload := helps.JSONPayload(line); len(payload) > 0 && gjson.GetBytes(payload, "type").String() == "message_stop" {
				hasMessageStop = true
			}
			line = restoreClaudeOAuthToolNamesFromStreamLine(line, claudeToolPrefix, auth.ToolPrefixDisabled(), oauthToolNamesReverseMap)
			line = e.restoreResponseModel(line, req.Model)
			chunks := sdktranslator.TranslateStream(
				ctx,
				to,
				responseFormat,
				req.Model,
				opts.OriginalRequest,
				bodyForTranslation,
				bytes.Clone(line),
				&param,
			)
			for i := range chunks {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
				case <-ctx.Done():
					return
				}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			reporter.PublishFailure(ctx, errScan)
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: errScan}:
			case <-ctx.Done():
			}
			return
		}
		if !hasMessageStop {
			errMissingStop := claudeStreamProtocolErrorf("stream response ended before message_stop")
			helps.RecordAPIResponseError(ctx, e.cfg, errMissingStop)
			reporter.PublishFailure(ctx, errMissingStop)
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: errMissingStop}:
			case <-ctx.Done():
			}
		} else if syntheticFirstPartyOAuth {
			storeClaudePreviousRequest(previousRequestScope, httpResp.Header.Get("request-id"))
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

type claudeMessageStreamAccumulator struct {
	message          map[string]any
	content          []any
	inputJSONBuffers map[int]string
	openContentIndex int
	started          bool
	messageDeltaSeen bool
	stopped          bool
}

func newClaudeMessageStreamAccumulator() *claudeMessageStreamAccumulator {
	return &claudeMessageStreamAccumulator{
		inputJSONBuffers: make(map[int]string),
		openContentIndex: -1,
	}
}

// aggregateClaudeMessageStream follows the accumulation behavior of the
// Anthropic Go/TypeScript SDK MessageStream while adding protocol validation
// suitable for Execute, where a truncated SSE response must never be returned
// as a successful non-stream Message. Each data line is transformed before it
// is parsed so response model and OAuth tool names are restored in the snapshot
// itself, not as a lossy post-processing pass.
func aggregateClaudeMessageStream(data []byte, transformDataLine func([]byte) []byte) ([]byte, []byte, error) {
	accumulator := newClaudeMessageStreamAccumulator()
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, 52_428_800)

	var restoredStream bytes.Buffer
	pendingEvent := ""
	hasDataLine := false
	for scanner.Scan() {
		line := bytes.Clone(scanner.Bytes())
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("data:")) && transformDataLine != nil {
			line = transformDataLine(line)
			trimmed = bytes.TrimSpace(line)
		}
		restoredStream.Write(line)
		restoredStream.WriteByte('\n')

		if len(trimmed) == 0 {
			pendingEvent = ""
			continue
		}
		if bytes.HasPrefix(trimmed, []byte(":")) || bytes.HasPrefix(trimmed, []byte("id:")) || bytes.HasPrefix(trimmed, []byte("retry:")) {
			continue
		}
		if bytes.HasPrefix(trimmed, []byte("event:")) {
			if pendingEvent != "" {
				return nil, nil, claudeStreamProtocolErrorf("received event %q before data for event %q", strings.TrimSpace(string(trimmed[len("event:"):])), pendingEvent)
			}
			pendingEvent = strings.TrimSpace(string(trimmed[len("event:"):]))
			if pendingEvent == "" {
				return nil, nil, claudeStreamProtocolErrorf("received an empty event name")
			}
			continue
		}
		if !bytes.HasPrefix(trimmed, []byte("data:")) {
			return nil, nil, claudeStreamProtocolErrorf("received an unsupported SSE field")
		}

		hasDataLine = true
		payload := bytes.TrimSpace(trimmed[len("data:"):])
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			return nil, nil, claudeStreamProtocolErrorf("received an empty or non-Anthropic data event")
		}
		event, errDecode := decodeClaudeStreamJSONObject(payload, "event")
		if errDecode != nil {
			return nil, nil, errDecode
		}
		eventType, okType := claudeStreamString(event, "type")
		if !okType || strings.TrimSpace(eventType) == "" {
			return nil, nil, claudeStreamProtocolErrorf("event is missing type")
		}
		if pendingEvent != "" && pendingEvent != eventType {
			return nil, nil, claudeStreamProtocolErrorf("event label %q does not match data type %q", pendingEvent, eventType)
		}
		pendingEvent = ""
		if errAccumulate := accumulator.add(eventType, event); errAccumulate != nil {
			return nil, nil, errAccumulate
		}
	}
	if errScan := scanner.Err(); errScan != nil {
		return nil, nil, errScan
	}
	if pendingEvent != "" {
		return nil, nil, claudeStreamProtocolErrorf("stream ended before data for event %q", pendingEvent)
	}
	if !hasDataLine {
		return nil, nil, claudeStreamProtocolErrorf("upstream returned empty stream response")
	}
	if !accumulator.started {
		return nil, nil, claudeStreamProtocolErrorf("stream response is missing message_start")
	}
	if !accumulator.stopped {
		return nil, nil, claudeStreamProtocolErrorf("stream response ended before message_stop")
	}

	message, errMarshal := json.Marshal(accumulator.message)
	if errMarshal != nil {
		return nil, nil, claudeStreamProtocolErrorf("marshal accumulated Message: %v", errMarshal)
	}
	return message, restoredStream.Bytes(), nil
}

func claudeStreamProtocolErrorf(format string, args ...any) error {
	return statusErr{code: http.StatusBadGateway, msg: "claude executor: " + fmt.Sprintf(format, args...)}
}

func decodeClaudeStreamJSONObject(payload []byte, label string) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var decoded any
	if errDecode := decoder.Decode(&decoded); errDecode != nil {
		return nil, claudeStreamProtocolErrorf("malformed stream %s: %v", label, errDecode)
	}
	if errTrailing := decoder.Decode(&struct{}{}); errTrailing != io.EOF {
		return nil, claudeStreamProtocolErrorf("stream %s contains trailing JSON data", label)
	}
	object, okObject := decoded.(map[string]any)
	if !okObject || object == nil {
		return nil, claudeStreamProtocolErrorf("stream %s must be a JSON object", label)
	}
	return object, nil
}

func decodeClaudeStreamJSONValue(payload string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.UseNumber()
	var decoded any
	if errDecode := decoder.Decode(&decoded); errDecode != nil {
		return nil, errDecode
	}
	if errTrailing := decoder.Decode(&struct{}{}); errTrailing != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return decoded, nil
}

func claudeStreamString(object map[string]any, key string) (string, bool) {
	value, exists := object[key]
	if !exists {
		return "", false
	}
	stringValue, okString := value.(string)
	return stringValue, okString
}

func claudeStreamObject(object map[string]any, key string) (map[string]any, bool) {
	value, exists := object[key]
	if !exists {
		return nil, false
	}
	objectValue, okObject := value.(map[string]any)
	return objectValue, okObject && objectValue != nil
}

func claudeStreamIndex(event map[string]any) (int, error) {
	value, exists := event["index"]
	if !exists {
		return 0, claudeStreamProtocolErrorf("content event is missing index")
	}
	number, okNumber := value.(json.Number)
	if !okNumber {
		return 0, claudeStreamProtocolErrorf("content event index is not an integer")
	}
	parsed, errParse := strconv.ParseInt(number.String(), 10, 32)
	if errParse != nil || parsed < 0 {
		return 0, claudeStreamProtocolErrorf("content event index %q is invalid", number.String())
	}
	return int(parsed), nil
}

func (a *claudeMessageStreamAccumulator) add(eventType string, event map[string]any) error {
	if a.stopped && eventType != "ping" {
		return claudeStreamProtocolErrorf("received %s after message_stop", eventType)
	}

	switch eventType {
	case "ping":
		return nil
	case "error":
		errorObject, _ := claudeStreamObject(event, "error")
		errorType, _ := claudeStreamString(errorObject, "type")
		message, _ := claudeStreamString(errorObject, "message")
		if strings.TrimSpace(message) == "" {
			message = strings.TrimSpace(errorType)
		}
		if message == "" {
			message = "unknown upstream error"
		}
		return claudeStreamProtocolErrorf("upstream returned error event: %s", message)
	case "message_start":
		return a.startMessage(event)
	case "content_block_start":
		return a.startContent(event)
	case "content_block_delta":
		return a.addContentDelta(event)
	case "content_block_stop":
		return a.stopContent(event)
	case "message_delta":
		return a.addMessageDelta(event)
	case "message_stop":
		return a.stopMessage()
	default:
		return nil
	}
}

func (a *claudeMessageStreamAccumulator) startMessage(event map[string]any) error {
	if a.started {
		return claudeStreamProtocolErrorf("received message_start before the previous message_stop")
	}
	message, okMessage := claudeStreamObject(event, "message")
	if !okMessage {
		return claudeStreamProtocolErrorf("message_start is missing message")
	}
	id, okID := claudeStreamString(message, "id")
	model, okModel := claudeStreamString(message, "model")
	messageType, okMessageType := claudeStreamString(message, "type")
	role, okRole := claudeStreamString(message, "role")
	content, okContent := message["content"].([]any)
	_, okUsage := message["usage"].(map[string]any)
	if !okID || strings.TrimSpace(id) == "" || !okModel || strings.TrimSpace(model) == "" {
		return claudeStreamProtocolErrorf("message_start message is missing id or model")
	}
	if !okMessageType || messageType != "message" || !okRole || role != "assistant" {
		return claudeStreamProtocolErrorf("message_start message has invalid type or role")
	}
	if !okContent || len(content) != 0 || !okUsage {
		return claudeStreamProtocolErrorf("message_start message must contain empty content and usage")
	}
	a.message = message
	a.content = content
	a.started = true
	return nil
}

func (a *claudeMessageStreamAccumulator) requireActive(eventType string) error {
	if !a.started {
		return claudeStreamProtocolErrorf("received %s before message_start", eventType)
	}
	if a.messageDeltaSeen {
		return claudeStreamProtocolErrorf("received %s after message_delta", eventType)
	}
	return nil
}

func (a *claudeMessageStreamAccumulator) startContent(event map[string]any) error {
	if errActive := a.requireActive("content_block_start"); errActive != nil {
		return errActive
	}
	if a.openContentIndex >= 0 {
		return claudeStreamProtocolErrorf("received content_block_start before content_block_stop for index %d", a.openContentIndex)
	}
	index, errIndex := claudeStreamIndex(event)
	if errIndex != nil {
		return errIndex
	}
	if index != len(a.content) {
		return claudeStreamProtocolErrorf("content_block_start index %d is out of order; expected %d", index, len(a.content))
	}
	contentBlock, okBlock := claudeStreamObject(event, "content_block")
	blockType, okType := claudeStreamString(contentBlock, "type")
	if !okBlock || !okType || strings.TrimSpace(blockType) == "" {
		return claudeStreamProtocolErrorf("content_block_start is missing a typed content_block")
	}
	a.content = append(a.content, contentBlock)
	a.message["content"] = a.content
	// The beta fallback block is a model boundary. Anthropic's official SDK
	// updates the accumulated Message model to the model serving the content
	// after that boundary while retaining the block in content for replay.
	if blockType == "fallback" {
		to, okTo := claudeStreamObject(contentBlock, "to")
		toModel, okToModel := claudeStreamString(to, "model")
		if !okTo || !okToModel || strings.TrimSpace(toModel) == "" {
			return claudeStreamProtocolErrorf("fallback content block is missing to.model")
		}
		a.message["model"] = toModel
	}
	a.openContentIndex = index
	return nil
}

func (a *claudeMessageStreamAccumulator) activeContent(eventType string, event map[string]any) (int, map[string]any, error) {
	if errActive := a.requireActive(eventType); errActive != nil {
		return 0, nil, errActive
	}
	index, errIndex := claudeStreamIndex(event)
	if errIndex != nil {
		return 0, nil, errIndex
	}
	if index != a.openContentIndex || index < 0 || index >= len(a.content) {
		return 0, nil, claudeStreamProtocolErrorf("%s index %d has no active content block", eventType, index)
	}
	contentBlock, okBlock := a.content[index].(map[string]any)
	if !okBlock {
		return 0, nil, claudeStreamProtocolErrorf("content block %d is invalid", index)
	}
	return index, contentBlock, nil
}

func (a *claudeMessageStreamAccumulator) addContentDelta(event map[string]any) error {
	index, contentBlock, errContent := a.activeContent("content_block_delta", event)
	if errContent != nil {
		return errContent
	}
	delta, okDelta := claudeStreamObject(event, "delta")
	deltaType, okDeltaType := claudeStreamString(delta, "type")
	blockType, _ := claudeStreamString(contentBlock, "type")
	if !okDelta || !okDeltaType {
		return claudeStreamProtocolErrorf("content_block_delta is missing a typed delta")
	}

	appendString := func(blockField, deltaField string) error {
		deltaValue, okDeltaValue := claudeStreamString(delta, deltaField)
		blockValue, okBlockValue := claudeStreamString(contentBlock, blockField)
		if !okDeltaValue || !okBlockValue {
			return claudeStreamProtocolErrorf("%s has invalid %s content", deltaType, deltaField)
		}
		contentBlock[blockField] = blockValue + deltaValue
		return nil
	}

	switch deltaType {
	case "text_delta":
		if blockType != "text" {
			return claudeStreamProtocolErrorf("text_delta targets %s block", blockType)
		}
		return appendString("text", "text")
	case "citations_delta":
		if blockType != "text" {
			return claudeStreamProtocolErrorf("citations_delta targets %s block", blockType)
		}
		citation, okCitation := claudeStreamObject(delta, "citation")
		if !okCitation {
			return claudeStreamProtocolErrorf("citations_delta is missing citation")
		}
		var citations []any
		switch existing := contentBlock["citations"].(type) {
		case nil:
		case []any:
			citations = existing
		default:
			return claudeStreamProtocolErrorf("text block citations is not an array or null")
		}
		contentBlock["citations"] = append(citations, citation)
		return nil
	case "input_json_delta":
		if blockType != "tool_use" && blockType != "server_tool_use" && blockType != "mcp_tool_use" {
			return claudeStreamProtocolErrorf("input_json_delta targets %s block", blockType)
		}
		partialJSON, okPartialJSON := claudeStreamString(delta, "partial_json")
		if !okPartialJSON {
			return claudeStreamProtocolErrorf("input_json_delta is missing partial_json")
		}
		a.inputJSONBuffers[index] += partialJSON
		return nil
	case "thinking_delta":
		if blockType != "thinking" {
			return claudeStreamProtocolErrorf("thinking_delta targets %s block", blockType)
		}
		return appendString("thinking", "thinking")
	case "signature_delta":
		if blockType != "thinking" {
			return claudeStreamProtocolErrorf("signature_delta targets %s block", blockType)
		}
		signature, okSignature := claudeStreamString(delta, "signature")
		if !okSignature {
			return claudeStreamProtocolErrorf("signature_delta is missing signature")
		}
		contentBlock["signature"] = signature
		return nil
	case "compaction_delta":
		if blockType != "compaction" {
			return claudeStreamProtocolErrorf("compaction_delta targets %s block", blockType)
		}
		// Anthropic emits the complete compaction payload in one delta. Both
		// fields are nullable and optional in the SDK model; omitted fields
		// therefore have the same final value as explicit JSON null.
		for _, field := range []string{"content", "encrypted_content"} {
			value := delta[field]
			if value != nil {
				if _, okString := value.(string); !okString {
					return claudeStreamProtocolErrorf("compaction_delta has invalid %s content", field)
				}
			}
			contentBlock[field] = value
		}
		return nil
	default:
		return nil
	}
}

func (a *claudeMessageStreamAccumulator) stopContent(event map[string]any) error {
	index, contentBlock, errContent := a.activeContent("content_block_stop", event)
	if errContent != nil {
		return errContent
	}
	if bufferedInput, exists := a.inputJSONBuffers[index]; exists {
		if strings.TrimSpace(bufferedInput) == "" {
			return claudeStreamProtocolErrorf("tool input stream for content block %d is empty", index)
		}
		parsedInput, errParse := decodeClaudeStreamJSONValue(bufferedInput)
		if errParse != nil {
			return claudeStreamProtocolErrorf("tool input stream for content block %d is invalid JSON: %v", index, errParse)
		}
		contentBlock["input"] = parsedInput
		delete(a.inputJSONBuffers, index)
	}
	a.openContentIndex = -1
	return nil
}

func (a *claudeMessageStreamAccumulator) addMessageDelta(event map[string]any) error {
	if !a.started {
		return claudeStreamProtocolErrorf("received message_delta before message_start")
	}
	if a.openContentIndex >= 0 {
		return claudeStreamProtocolErrorf("received message_delta before content_block_stop for index %d", a.openContentIndex)
	}
	delta, okDelta := claudeStreamObject(event, "delta")
	if !okDelta {
		return claudeStreamProtocolErrorf("message_delta is missing delta")
	}
	if _, hasStopReason := delta["stop_reason"]; !hasStopReason {
		return claudeStreamProtocolErrorf("message_delta is missing stop_reason")
	}
	for key, value := range delta {
		a.message[key] = value
	}
	for key, value := range event {
		switch key {
		case "type", "delta", "usage":
			continue
		default:
			a.message[key] = value
		}
	}
	usageDelta, okUsageDelta := claudeStreamObject(event, "usage")
	usage, okUsage := a.message["usage"].(map[string]any)
	if !okUsageDelta || !okUsage {
		return claudeStreamProtocolErrorf("message_delta or message_start is missing usage")
	}
	for key, value := range usageDelta {
		// Optional cumulative usage members are nullable on later deltas. The
		// official SDK keeps the last numeric/object value when a later frame
		// carries null rather than erasing the accumulated snapshot.
		if value != nil {
			usage[key] = value
		}
	}
	a.messageDeltaSeen = true
	return nil
}

func (a *claudeMessageStreamAccumulator) stopMessage() error {
	if !a.started {
		return claudeStreamProtocolErrorf("received message_stop before message_start")
	}
	if a.openContentIndex >= 0 {
		return claudeStreamProtocolErrorf("received message_stop before content_block_stop for index %d", a.openContentIndex)
	}
	if !a.messageDeltaSeen {
		return claudeStreamProtocolErrorf("received message_stop before message_delta")
	}
	a.stopped = true
	return nil
}

func validateClaudeStreamingResponse(data []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, 52_428_800)

	hasData := false
	hasMessageStart := false
	hasMessageDelta := false
	hasMessageStop := false

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		hasData = true
		if !gjson.ValidBytes(payload) {
			return statusErr{code: http.StatusBadGateway, msg: "claude executor: upstream returned malformed stream data"}
		}

		root := gjson.ParseBytes(payload)
		switch root.Get("type").String() {
		case "error":
			message := strings.TrimSpace(root.Get("error.message").String())
			if message == "" {
				message = strings.TrimSpace(root.Get("error.type").String())
			}
			if message == "" {
				message = "unknown upstream error"
			}
			return statusErr{code: http.StatusBadGateway, msg: "claude executor: upstream returned error event: " + message}
		case "message_start":
			message := root.Get("message")
			if strings.TrimSpace(message.Get("id").String()) == "" || strings.TrimSpace(message.Get("model").String()) == "" {
				return statusErr{code: http.StatusBadGateway, msg: "claude executor: upstream stream message_start is missing id or model"}
			}
			hasMessageStart = true
		case "message_delta":
			hasMessageDelta = true
		case "message_stop":
			hasMessageStop = true
		}
	}
	if errScan := scanner.Err(); errScan != nil {
		return errScan
	}
	if !hasData {
		return statusErr{code: http.StatusBadGateway, msg: "claude executor: upstream returned empty stream response"}
	}
	if !hasMessageStart {
		return statusErr{code: http.StatusBadGateway, msg: "claude executor: upstream stream response is missing message_start"}
	}
	if !hasMessageDelta {
		return statusErr{code: http.StatusBadGateway, msg: "claude executor: upstream stream response ended before message completion"}
	}
	if !hasMessageStop {
		return statusErr{code: http.StatusBadGateway, msg: "claude executor: upstream stream response ended before message_stop"}
	}
	return nil
}

var claudeCountTokensBodyFields = map[string]struct{}{
	"cache_control":      {},
	"context_management": {},
	"mcp_servers":        {},
	"messages":           {},
	"model":              {},
	"output_config":      {},
	"output_format":      {},
	"speed":              {},
	"system":             {},
	"thinking":           {},
	"tool_choice":        {},
	"tools":              {},
}

func projectClaudeCountTokensBody(body []byte) ([]byte, error) {
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		return nil, fmt.Errorf("Claude count_tokens body must be a JSON object")
	}

	var projected bytes.Buffer
	projected.WriteByte('{')
	first := true
	root.ForEach(func(key, value gjson.Result) bool {
		if _, allowed := claudeCountTokensBodyFields[key.String()]; !allowed {
			return true
		}
		if !first {
			projected.WriteByte(',')
		}
		first = false
		projected.WriteString(strconv.Quote(key.String()))
		projected.WriteByte(':')
		projected.WriteString(value.Raw)
		return true
	})
	projected.WriteByte('}')

	result := projected.Bytes()
	if !gjson.GetBytes(result, "model").Exists() || !gjson.GetBytes(result, "messages").Exists() {
		return nil, fmt.Errorf("Claude count_tokens body requires model and messages")
	}
	return result, nil
}

func (e *ClaudeExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	ctx, opts.Headers = resolveClaudeClientContext(ctx, opts.Headers)
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	upstreamModel := e.upstreamModel(baseModel)

	apiKey, baseURL := claudeCreds(auth)
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}

	from := opts.SourceFormat
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	to := sdktranslator.FromString("claude")
	// Use streaming translation to preserve function calling, except for claude.
	stream := from != to
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, stream)
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, stream)
	body = setClaudeRequestModel(body, upstreamModel)
	var err error
	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	if rebuildMidSystemMessageEnabled(e.cfg, auth) {
		body = rebuildMidSystemMessagesToTopLevel(body)
	}
	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, requestedModel, requestPath, opts.Headers)
	effectiveModel := strings.TrimSpace(gjson.GetBytes(body, "model").String())
	if effectiveModel == "" {
		effectiveModel = baseModel
	}
	canonicalSessionID, errSessionID := resolveClaudeCanonicalSessionIDRequired(ctx, body, originalPayload, opts.Headers, opts.Metadata, req.Metadata)
	if errSessionID != nil {
		return cliproxyexecutor.Response{}, errSessionID
	}
	if errIdentity := validateClaudeClientOAuthAccount(ctx, auth, apiKey, baseURL, body, originalPayload); errIdentity != nil {
		return cliproxyexecutor.Response{}, errIdentity
	}
	ctx, err = withClaudeCanonicalSessionIDRequired(ctx, canonicalSessionID)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	cloakRequest := shouldApplyClaudeCloaking(ctx, e.cfg, auth)
	ctx = withClaudeCloakDecision(ctx, cloakRequest)
	oauthMode := isClaudeOAuthAuth(auth, apiKey)
	firstPartyClaude := isClaudeFirstPartyBaseURL(baseURL)
	firstPartyOAuth := oauthMode && firstPartyClaude
	syntheticFirstPartyOAuth := cloakRequest && firstPartyOAuth && !helps.IsClaudeCodeClientUserAgent(getClientUserAgent(ctx))
	if syntheticFirstPartyOAuth {
		body = ensureClaudeCodeToolsArray(body)
	}

	// Claude Code's count_tokens path does not call its messages-create billing
	// wrapper: preserve caller fields and the explicit tools array, but do not
	// synthesize system/CCH/identity.
	// Extract explicit betas to the header as required by the API.
	var extraBetas []string
	extraBetas, body = extractAndRemoveBetas(body)
	if syntheticFirstPartyOAuth {
		extraBetas = appendSyntheticClaudeCodeConditionalBetas(extraBetas, body, effectiveModel, false)
	}
	if cloakRequest && firstPartyOAuth {
		body, _ = prepareClaudeOAuthToolNamesForUpstream(body, claudeToolPrefix, auth.ToolPrefixDisabled())
	}
	body = sanitizeClaudeMessagesForClaudeUpstreamWithDebug(ctx, body, effectiveModel)
	body, err = projectClaudeCountTokensBody(body)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}

	url := fmt.Sprintf("%s/v1/messages/count_tokens?beta=true", baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	if errHeaders := applyClaudeHeadersForBodyAndModel(httpReq, auth, apiKey, false, extraBetas, e.cfg, opts.Headers, body, requestedModel); errHeaders != nil {
		return cliproxyexecutor.Response{}, errHeaders
	}
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      body,
		Provider:  e.upstreamRequestLogProvider(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return cliproxyexecutor.Response{}, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, resp.StatusCode, resp.Header.Clone())
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Decompress error responses — pass the Content-Encoding value (may be empty)
		// and let decodeResponseBody handle both header-declared and magic-byte-detected
		// compression.  This keeps error-path behaviour consistent with the success path.
		errBody, decErr := decodeResponseBody(resp.Body, resp.Header.Get("Content-Encoding"))
		if decErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, decErr)
			msg := fmt.Sprintf("failed to decode error response body: %v", decErr)
			helps.LogWithRequestID(ctx).Warn(msg)
			return cliproxyexecutor.Response{}, statusErr{code: resp.StatusCode, msg: msg}
		}
		b, readErr := io.ReadAll(errBody)
		if readErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, readErr)
			msg := fmt.Sprintf("failed to read error response body: %v", readErr)
			helps.LogWithRequestID(ctx).Warn(msg)
			b = []byte(msg)
		}
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		if errClose := errBody.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return cliproxyexecutor.Response{}, statusErr{code: resp.StatusCode, msg: string(b)}
	}
	decodedBody, err := decodeResponseBody(resp.Body, resp.Header.Get("Content-Encoding"))
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return cliproxyexecutor.Response{}, err
	}
	defer func() {
		if errClose := decodedBody.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
	}()
	data, err := io.ReadAll(decodedBody)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return cliproxyexecutor.Response{}, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, data)
	count := gjson.GetBytes(data, "input_tokens").Int()
	out := sdktranslator.TranslateTokenCount(ctx, to, responseFormat, count, data)
	return cliproxyexecutor.Response{Payload: out, Headers: resp.Header.Clone()}, nil
}

func (e *ClaudeExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	log.Debugf("claude executor: refresh called")
	if refreshed, handled, err := helps.RefreshAuthViaHome(ctx, e.cfg, auth); handled {
		if err == nil {
			preserveClaudeOAuthIdentity(auth, refreshed)
		}
		return refreshed, err
	}
	if auth == nil {
		return nil, fmt.Errorf("claude executor: auth is nil")
	}
	storageAtStart, _ := auth.Storage.(*claudeauth.ClaudeTokenStorage)
	var refreshToken string
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["refresh_token"].(string); ok && v != "" {
			refreshToken = v
		}
	}
	if refreshToken == "" && storageAtStart != nil {
		refreshToken = strings.TrimSpace(storageAtStart.RefreshToken)
	}
	if refreshToken == "" {
		return auth, nil
	}
	failedAccessToken := metadataString(auth.Metadata, "access_token")
	if failedAccessToken == "" && storageAtStart != nil {
		failedAccessToken = strings.TrimSpace(storageAtStart.AccessToken)
	}
	credentialPath := claudeOAuthCredentialPath(e.cfg, auth)
	refreshFileLock, errLock := acquireClaudeOAuthRefreshFileLock(ctx, credentialPath)
	if errLock != nil {
		return nil, errLock
	}
	if refreshFileLock != nil {
		defer refreshFileLock.release()
		diskStorage, diskMetadata, errRead := readClaudeOAuthCredential(credentialPath)
		if errRead != nil && !os.IsNotExist(errRead) {
			return nil, fmt.Errorf("read Claude OAuth credential before refresh: %w", errRead)
		}
		if errRead == nil {
			hydrateClaudeOAuthStorageAliases(diskStorage, diskMetadata)
			diskAccessToken := strings.TrimSpace(diskStorage.AccessToken)
			diskRefreshToken := strings.TrimSpace(diskStorage.RefreshToken)
			if storageAtStart == nil {
				adoptClaudeOAuthCredential(auth, diskStorage, diskMetadata)
				storageAtStart = diskStorage
			}
			if diskAccessToken != failedAccessToken || diskRefreshToken != refreshToken {
				adoptClaudeOAuthCredential(auth, diskStorage, diskMetadata)
				storageAtStart = diskStorage
				if diskAccessToken != failedAccessToken {
					if diskAccessToken == "" || diskRefreshToken == "" {
						return nil, statusErr{code: http.StatusUnauthorized, msg: "Claude OAuth refresh token is no longer valid"}
					}
					return auth, nil
				}
				if diskRefreshToken == "" {
					return nil, statusErr{code: http.StatusUnauthorized, msg: "Claude OAuth refresh token is no longer valid"}
				}
				refreshToken = diskRefreshToken
			}
		}
	}
	storedScopes := []string(nil)
	if storage, okStorage := auth.Storage.(*claudeauth.ClaudeTokenStorage); okStorage && storage != nil {
		storedScopes = append(storedScopes, storage.Scopes...)
	}
	if len(storedScopes) == 0 && auth.Metadata != nil {
		switch scopes := auth.Metadata["scopes"].(type) {
		case []string:
			storedScopes = append(storedScopes, scopes...)
		case []any:
			for _, scope := range scopes {
				if value, okString := scope.(string); okString && strings.TrimSpace(value) != "" {
					storedScopes = append(storedScopes, strings.TrimSpace(value))
				}
			}
		case string:
			storedScopes = strings.Fields(scopes)
		}
	}
	subscriptionType := metadataString(auth.Metadata, "subscription_type")
	if subscriptionType == "" {
		subscriptionType = metadataString(auth.Metadata, "subscriptionType")
	}
	if subscriptionType == "" && storageAtStart != nil {
		subscriptionType = strings.TrimSpace(storageAtStart.SubscriptionType)
	}
	rateLimitTier := metadataString(auth.Metadata, "rate_limit_tier")
	if rateLimitTier == "" {
		rateLimitTier = metadataString(auth.Metadata, "rateLimitTier")
	}
	if rateLimitTier == "" && storageAtStart != nil {
		rateLimitTier = strings.TrimSpace(storageAtStart.RateLimitTier)
	}
	clientID := metadataString(auth.Metadata, "client_id")
	if clientID == "" {
		clientID = metadataString(auth.Metadata, "clientId")
	}
	if clientID == "" && storageAtStart != nil {
		clientID = strings.TrimSpace(storageAtStart.ClientID)
	}
	svc := claudeauth.NewClaudeAuthWithProxyURL(e.cfg, auth.ProxyURL)
	td, err := svc.RefreshTokensWithScopesAndRetry(ctx, refreshToken, storedScopes, subscriptionType, rateLimitTier, clientID, 3)
	if err != nil {
		// A sibling process may have rotated and persisted the credential while
		// this request was in flight. Adopt that token before declaring failure.
		if refreshFileLock != nil {
			if diskStorage, diskMetadata, errRead := readClaudeOAuthCredential(credentialPath); errRead == nil {
				hydrateClaudeOAuthStorageAliases(diskStorage, diskMetadata)
				if diskAccessToken := strings.TrimSpace(diskStorage.AccessToken); diskAccessToken != "" && diskAccessToken != failedAccessToken {
					adoptClaudeOAuthCredential(auth, diskStorage, diskMetadata)
					return auth, nil
				}
			}
		}
		if claudeauth.IsInvalidGrantError(err) {
			if auth.Metadata == nil {
				auth.Metadata = make(map[string]any)
			}
			if metadataString(auth.Metadata, "refresh_token") == refreshToken {
				auth.Metadata["access_token"] = ""
				auth.Metadata["refresh_token"] = ""
				auth.Metadata["expired"] = ""
			}
			if currentStorage, okStorage := auth.Storage.(*claudeauth.ClaudeTokenStorage); okStorage && currentStorage != nil && currentStorage.RefreshToken == refreshToken {
				clearedStorage := currentStorage.Clone()
				clearedStorage.AccessToken = ""
				clearedStorage.RefreshToken = ""
				clearedStorage.Expire = ""
				auth.Storage = clearedStorage
				if refreshFileLock != nil {
					if errSave := persistClaudeOAuthCredential(credentialPath, auth); errSave != nil {
						log.Errorf("failed to clear dead Claude OAuth refresh token: %v", errSave)
					}
				}
			}
		}
		return nil, err
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = td.AccessToken
	if td.RefreshToken != "" {
		auth.Metadata["refresh_token"] = td.RefreshToken
	}
	if td.Email != "" {
		auth.Metadata["email"] = td.Email
	}
	if td.AccountUUID != "" {
		auth.Metadata["account_uuid"] = td.AccountUUID
	}
	if td.OrganizationUUID != "" {
		auth.Metadata["organization_uuid"] = td.OrganizationUUID
	}
	if scopes := strings.Fields(td.Scope); len(scopes) > 0 {
		auth.Metadata["scopes"] = scopes
	}
	if td.RefreshTokenExpiresAt > 0 {
		auth.Metadata["refresh_token_expires_at"] = td.RefreshTokenExpiresAt
	}
	if td.SubscriptionType != "" {
		auth.Metadata["subscription_type"] = td.SubscriptionType
	}
	if td.RateLimitTier != "" {
		auth.Metadata["rate_limit_tier"] = td.RateLimitTier
	}
	auth.Metadata["client_id"] = td.ClientID
	auth.Metadata["expired"] = td.Expire
	auth.Metadata["type"] = "claude"
	now := time.Now().Format(time.RFC3339)
	auth.Metadata["last_refresh"] = now
	if storage, okStorage := auth.Storage.(*claudeauth.ClaudeTokenStorage); okStorage && storage != nil {
		updatedStorage := storage.Clone()
		svc.UpdateTokenStorage(updatedStorage, td)
		auth.Storage = updatedStorage
	}
	if refreshFileLock != nil {
		if errSave := persistClaudeOAuthCredential(credentialPath, auth); errSave != nil {
			return nil, fmt.Errorf("persist refreshed Claude OAuth credential: %w", errSave)
		}
	}
	return auth, nil
}

func preserveClaudeOAuthIdentity(previous, refreshed *cliproxyauth.Auth) {
	if previous == nil || refreshed == nil {
		return
	}
	if refreshed.Metadata == nil {
		refreshed.Metadata = make(map[string]any)
	}
	for _, key := range []string{"email", "account_uuid", "organization_uuid", "refresh_token"} {
		if metadataString(refreshed.Metadata, key) == "" {
			if value := metadataString(previous.Metadata, key); value != "" {
				refreshed.Metadata[key] = value
			}
		}
	}
	if refreshed.Attributes == nil {
		refreshed.Attributes = make(map[string]string)
	}
	for _, key := range []string{"auth_kind", "account_uuid", "organization_uuid"} {
		if strings.TrimSpace(refreshed.Attributes[key]) == "" && previous.Attributes != nil {
			if value := strings.TrimSpace(previous.Attributes[key]); value != "" {
				refreshed.Attributes[key] = value
			}
		}
	}
}

// extractAndRemoveBetas extracts the "betas" array from the body and removes it.
// Returns the extracted betas as a string slice and the modified body.
func extractAndRemoveBetas(body []byte) ([]string, []byte) {
	betasResult := gjson.GetBytes(body, "betas")
	if !betasResult.Exists() {
		return nil, body
	}
	var betas []string
	if betasResult.IsArray() {
		for _, item := range betasResult.Array() {
			if s := strings.TrimSpace(item.String()); s != "" {
				betas = append(betas, s)
			}
		}
	} else if s := strings.TrimSpace(betasResult.String()); s != "" {
		betas = append(betas, s)
	}
	body, _ = sjson.DeleteBytes(body, "betas")
	return betas, body
}

func claudeAdvancedToolUseEnabled(body []byte) bool {
	tools := gjson.GetBytes(body, "tools")
	if !tools.IsArray() {
		return false
	}
	enabled := false
	tools.ForEach(func(_, tool gjson.Result) bool {
		name := strings.ToLower(strings.TrimSpace(tool.Get("name").String()))
		toolType := strings.ToLower(strings.TrimSpace(tool.Get("type").String()))
		if tool.Get("defer_loading").Bool() || name == "toolsearch" || name == "tool_search" || strings.Contains(toolType, "tool_search") {
			enabled = true
			return false
		}
		return true
	})
	return enabled
}

func claudeEffortEnabled(body []byte) bool {
	effort := gjson.GetBytes(body, "output_config.effort")
	return effort.Type == gjson.String && strings.TrimSpace(effort.String()) != ""
}

func appendSyntheticClaudeCodeConditionalBetas(betas []string, body []byte, model string, includeFallback bool) []string {
	if claudeAdvancedToolUseEnabled(body) {
		betas = append(betas, helps.ClaudeCodeAdvancedToolUseBeta)
	}
	if claudeEffortEnabled(body) {
		betas = append(betas, helps.ClaudeCodeEffortBeta)
	}
	if includeFallback && claudeCodeUsesFable5Fallback(model) {
		betas = append(betas, helps.ClaudeCodeServerSideFallbackBeta, helps.ClaudeCodeFallbackCreditBeta)
	}
	return betas
}

func ensureSyntheticClaudeCodeFallbacks(body []byte, model string) []byte {
	if !claudeCodeUsesFable5Fallback(model) || gjson.GetBytes(body, "fallbacks").Exists() {
		return body
	}
	updated, err := sjson.SetRawBytes(body, "fallbacks", []byte(`[{"model":"claude-opus-4-8"}]`))
	if err != nil {
		return body
	}
	return updated
}

func claudeCodeUsesFable5Fallback(model string) bool {
	return claudeCodeModelMatches(strings.ToLower(strings.TrimSpace(model)), "claude-fable-5")
}

func claudeCodeMidConversationSystemEnabled(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	if strings.HasPrefix(model, "claude-3-") {
		return false
	}
	if model == "claude-opus-4" || model == "claude-sonnet-4" ||
		strings.HasPrefix(model, "claude-opus-4-2025") || strings.HasPrefix(model, "claude-sonnet-4-2025") {
		return false
	}
	for _, unsupported := range []string{
		"claude-opus-4-0",
		"claude-opus-4-1",
		"claude-opus-4-5",
		"claude-opus-4-6",
		"claude-opus-4-7",
		"claude-sonnet-4-0",
		"claude-sonnet-4-5",
		"claude-sonnet-4-6",
		"claude-haiku-4-5",
	} {
		if claudeCodeModelMatches(model, unsupported) {
			return false
		}
	}
	return model != ""
}

func claudeCodeModelMatches(model, family string) bool {
	return model == family || strings.HasPrefix(model, family+"-") || strings.HasPrefix(model, family+"[")
}

// disableThinkingIfToolChoiceForced checks if tool_choice forces tool use and disables thinking.
// Anthropic API does not allow thinking when tool_choice is set to "any" or a specific tool.
// See: https://docs.anthropic.com/en/docs/build-with-claude/extended-thinking#important-considerations
func disableThinkingIfToolChoiceForced(body []byte) []byte {
	toolChoiceType := gjson.GetBytes(body, "tool_choice.type").String()
	// "auto" is allowed with thinking, but "any" or "tool" (specific tool) are not
	if toolChoiceType == "any" || toolChoiceType == "tool" {
		// Remove thinking configuration entirely to avoid API error
		body, _ = sjson.DeleteBytes(body, "thinking")
		// Adaptive thinking may also set output_config.effort; remove it to avoid
		// leaking thinking controls when tool_choice forces tool use.
		body, _ = sjson.DeleteBytes(body, "output_config.effort")
		if oc := gjson.GetBytes(body, "output_config"); oc.Exists() && oc.IsObject() && len(oc.Map()) == 0 {
			body, _ = sjson.DeleteBytes(body, "output_config")
		}
	}
	return body
}

// normalizeClaudeSamplingForUpstream keeps Anthropic message requests valid.
func normalizeClaudeSamplingForUpstream(body []byte) []byte {
	body, _ = sjson.DeleteBytes(body, "temperature")
	body, _ = sjson.DeleteBytes(body, "top_p")

	thinkingType := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "thinking.type").String()))
	switch thinkingType {
	case "enabled", "adaptive":
		body, _ = sjson.DeleteBytes(body, "top_p")
		body, _ = sjson.DeleteBytes(body, "top_k")
	}
	return body
}

// ensureClaudeThinkingDisplay defaults thinking.display to "summarized" when thinking
// is active and the client did not set display. Without this, Claude backends that
// enable redact-thinking return signature-only thinking blocks (empty thinking text).
// Explicit client values such as "omitted" are preserved.
func ensureClaudeThinkingDisplay(body []byte) []byte {
	thinkingType := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "thinking.type").String()))
	switch thinkingType {
	case "enabled", "adaptive":
	default:
		return body
	}
	if display := strings.TrimSpace(gjson.GetBytes(body, "thinking.display").String()); display != "" {
		return body
	}
	out, err := sjson.SetBytes(body, "thinking.display", "summarized")
	if err != nil {
		return body
	}
	return out
}

func claudeModelSupportsAdaptiveEffort(model string) bool {
	model = strings.TrimSpace(model)
	if info := registry.LookupModelInfo(model, "claude"); info != nil && info.Thinking != nil && len(info.Thinking.Levels) > 0 {
		return true
	}
	return strings.HasPrefix(model, "claude-sonnet-4-6-") ||
		strings.HasPrefix(model, "claude-opus-4-6-") ||
		model == "claude-sonnet-4-6" || model == "claude-opus-4-6"
}

func applySyntheticClaudeCodeThinkingProfile(body []byte, model string) []byte {
	toolChoice := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "tool_choice.type").String()))
	thinkingType := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "thinking.type").String()))
	explicitlyDisabled := thinkingType == "disabled"
	// Claude Code's B1i model gate disables the thinking request field for every
	// Claude 3 model, even when the downstream client supplied an explicit
	// enabled or disabled object.
	if strings.Contains(strings.ToLower(strings.TrimSpace(model)), "claude-3-") {
		body, _ = sjson.DeleteBytes(body, "thinking")
		thinkingType = ""
		explicitlyDisabled = false
	}
	rejectsDisabled := claudeCodeRejectsDisabledThinking(model)
	if explicitlyDisabled && rejectsDisabled {
		// Claude Code omits the entire thinking object for first-party models whose
		// API rejects the explicit disabled sentinel. It does not turn thinking on.
		body, _ = sjson.DeleteBytes(body, "thinking")
		thinkingType = ""
	} else if explicitlyDisabled {
		// The SDK's disabled-thinking sanitizer emits the canonical sentinel and
		// drops display, budgets, and unknown customer keys from that object.
		body, _ = sjson.SetRawBytes(body, "thinking", []byte(`{"type":"disabled"}`))
	}
	supportsAdaptive := claudeCodeSupportsAdaptiveThinking(model)
	if thinkingType == "enabled" && claudeCodeRejectsEnabledThinking(model) {
		// Opus 4.7/4.8, Sonnet 5, Fable 5, and Mythos 5 expose adaptive
		// thinking only. Claude Code canonicalizes a legacy budget request to
		// the adaptive sentinel instead of forwarding the rejected budget.
		body, _ = sjson.SetBytes(body, "thinking.type", "adaptive")
		body, _ = sjson.DeleteBytes(body, "thinking.budget_tokens")
		thinkingType = "adaptive"
	}
	if thinkingType == "" && !explicitlyDisabled {
		switch {
		case supportsAdaptive:
			body, _ = sjson.SetBytes(body, "thinking.type", "adaptive")
			thinkingType = "adaptive"
		case claudeCodeUsesLegacyThinking(model):
			body, _ = sjson.SetBytes(body, "thinking.type", "enabled")
			thinkingType = "enabled"
		}
	}
	defaultEffort := claudeCodeDefaultEffort(model)
	if defaultEffort != "" && !claudeEffortEnabled(body) {
		body, _ = sjson.SetBytes(body, "output_config.effort", defaultEffort)
	} else if defaultEffort == "" {
		body, _ = sjson.DeleteBytes(body, "output_config.effort")
		if outputConfig := gjson.GetBytes(body, "output_config"); outputConfig.Exists() && outputConfig.IsObject() && len(outputConfig.Map()) == 0 {
			body, _ = sjson.DeleteBytes(body, "output_config")
		}
	}
	switch thinkingType {
	case "enabled", "adaptive":
		// P4r is false for Haiku 4.5: the native client omits display even when
		// the caller supplied it. Claude 3 has already had thinking removed.
		if strings.Contains(strings.ToLower(strings.TrimSpace(model)), "claude-haiku-4-5") {
			body, _ = sjson.DeleteBytes(body, "thinking.display")
		}
		if thinkingType == "enabled" && claudeCodeUsesLegacyThinking(model) {
			maxTokens := int(gjson.GetBytes(body, "max_tokens").Int())
			if maxTokens <= 0 {
				maxTokens = claudeCodeDefaultMaxTokens(model)
			}
			if maxTokens > 0 {
				budgetResult := gjson.GetBytes(body, "thinking.budget_tokens")
				budget := int(budgetResult.Int())
				if !budgetResult.Exists() {
					budget = maxTokens - 1
				}
				if budget >= maxTokens {
					budget = maxTokens - 1
				}
				if budget < 1024 {
					budget = 1024
				}
				if budget > 0 {
					body, _ = sjson.SetBytes(body, "thinking.budget_tokens", budget)
				}
			}
			body = canonicalizeClaudeLegacyThinkingOrder(body)
		}
	default:
		body, _ = sjson.DeleteBytes(body, "thinking.display")
	}
	thinkingActive := thinkingType == "enabled" || thinkingType == "adaptive" || (explicitlyDisabled && rejectsDisabled)
	if toolChoice == "tool" && thinkingActive {
		body, _ = sjson.SetRawBytes(body, "tool_choice", []byte(`{"type":"auto"}`))
	}
	return body
}

// claudeCodeRejectsEnabledThinking lists the current first-party models whose
// API accepts adaptive thinking but rejects the legacy enabled/budget form.
func claudeCodeRejectsEnabledThinking(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	for _, adaptiveOnly := range []string{
		"claude-opus-4-7",
		"claude-opus-4-8",
		"claude-sonnet-5",
		"claude-fable-5",
		"claude-mythos-5",
	} {
		if strings.Contains(model, adaptiveOnly) {
			return true
		}
	}
	return false
}

// canonicalizeClaudeLegacyThinkingOrder mirrors the native object construction
// order used by Claude Code: budget_tokens precedes type. Remaining explicit
// client fields are retained in their original relative order.
func canonicalizeClaudeLegacyThinkingOrder(body []byte) []byte {
	thinking := gjson.GetBytes(body, "thinking")
	if !thinking.IsObject() {
		return body
	}

	values := make(map[string]string)
	inputOrder := make([]string, 0, len(thinking.Map()))
	thinking.ForEach(func(key, value gjson.Result) bool {
		name := key.String()
		if _, exists := values[name]; !exists {
			inputOrder = append(inputOrder, name)
		}
		values[name] = value.Raw
		return true
	})

	ordered := make([]string, 0, len(values))
	for _, name := range []string{"budget_tokens", "type"} {
		if _, exists := values[name]; exists {
			ordered = append(ordered, name)
		}
	}
	for _, name := range inputOrder {
		if name != "budget_tokens" && name != "type" {
			ordered = append(ordered, name)
		}
	}

	var object bytes.Buffer
	object.WriteByte('{')
	for index, name := range ordered {
		if index > 0 {
			object.WriteByte(',')
		}
		object.Write(marshalClaudeJSONString(name))
		object.WriteByte(':')
		object.WriteString(values[name])
	}
	object.WriteByte('}')

	updated, errSet := sjson.SetRawBytes(body, "thinking", object.Bytes())
	if errSet != nil {
		return body
	}
	return updated
}

// claudeCodeRejectsDisabledThinking is the first-party fallback encoded by
// Claude Code 2.1.216. The listed catalog models accept the explicit disabled
// sentinel; Fable 5, Mythos 5, and unknown/custom first-party models omit it.
func claudeCodeRejectsDisabledThinking(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	if strings.Contains(model, "claude-3-") || model == "claude-opus-4" || model == "claude-sonnet-4" {
		return false
	}
	for _, acceptsDisabled := range []string{
		"claude-opus-4-0",
		"claude-opus-4-1",
		"claude-opus-4-2025",
		"claude-opus-4-5",
		"claude-opus-4-6",
		"claude-opus-4-7",
		"claude-opus-4-8",
		"claude-sonnet-4-0",
		"claude-sonnet-4-2025",
		"claude-sonnet-4-5",
		"claude-sonnet-4-6",
		"claude-sonnet-5",
		"claude-haiku-4-5",
	} {
		if strings.Contains(model, acceptsDisabled) {
			return false
		}
	}
	return true
}

func claudeCodeUsesLegacyThinking(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	return claudeCodeDefaultMaxTokens(model) > 0 &&
		!strings.Contains(model, "claude-3-") &&
		!claudeCodeSupportsAdaptiveThinking(model)
}

func claudeCodeSupportsAdaptiveThinking(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	if model == "" || strings.Contains(model, "claude-3-") {
		return false
	}
	if model == "claude-opus-4" || model == "claude-sonnet-4" {
		return false
	}
	if claudeModelSupportsAdaptiveEffort(model) {
		return true
	}
	for _, legacy := range []string{
		"claude-haiku-4-5",
		"claude-sonnet-4-0",
		"claude-sonnet-4-2025",
		"claude-sonnet-4-5",
		"claude-opus-4-0",
		"claude-opus-4-1",
		"claude-opus-4-2025",
		"claude-opus-4-5",
	} {
		if strings.Contains(model, legacy) {
			return false
		}
	}
	return true
}

func claudeCodeUsesEffort(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	return claudeCodeSupportsAdaptiveThinking(model) || strings.Contains(model, "claude-opus-4-5")
}

func claudeCodeDefaultEffort(model string) string {
	if !claudeCodeUsesEffort(model) {
		return ""
	}
	// Claude Code 2.1.216's baked model catalog makes Opus 4.7 the sole
	// effort-capable model whose default differs from the provider fallback.
	if strings.Contains(strings.ToLower(strings.TrimSpace(model)), "claude-opus-4-7") {
		return "xhigh"
	}
	return "high"
}

func claudeCodeUsesInactiveTemperature(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	if strings.Contains(model, "claude-3-") || strings.Contains(model, "claude-haiku-4-5") {
		return true
	}
	return model == "claude-opus-4" ||
		model == "claude-sonnet-4" ||
		strings.Contains(model, "claude-opus-4-0") ||
		strings.Contains(model, "claude-opus-4-1") ||
		strings.Contains(model, "claude-opus-4-5") ||
		strings.Contains(model, "claude-opus-4-6") ||
		strings.Contains(model, "claude-opus-4-2025") ||
		strings.Contains(model, "claude-sonnet-4-0") ||
		strings.Contains(model, "claude-sonnet-4-5") ||
		strings.Contains(model, "claude-sonnet-4-6") ||
		strings.Contains(model, "claude-sonnet-4-2025")
}

func normalizeSyntheticClaudeCodeSampling(body []byte, model string) []byte {
	thinkingType := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "thinking.type").String()))
	if thinkingType == "enabled" || thinkingType == "adaptive" {
		return body
	}
	if !claudeCodeUsesInactiveTemperature(model) {
		return body
	}
	if !gjson.GetBytes(body, "temperature").Exists() {
		body, _ = sjson.SetBytes(body, "temperature", 1)
	}
	return body
}

func prepareClaudeCloakedThinking(body []byte, model string, firstPartyOAuth bool) []byte {
	if firstPartyOAuth {
		body = applySyntheticClaudeCodeThinkingProfile(body, model)
		return normalizeSyntheticClaudeCodeSampling(body, model)
	}
	body = disableThinkingIfToolChoiceForced(body)
	body = normalizeClaudeSamplingForUpstream(body)
	return ensureClaudeThinkingDisplay(body)
}

func ensureClaudeCodeContextManagement(body []byte) []byte {
	if gjson.GetBytes(body, "context_management").Exists() {
		return body
	}
	thinkingType := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "thinking.type").String()))
	switch thinkingType {
	case "enabled", "adaptive":
	default:
		return body
	}
	updated, errSet := sjson.SetRawBytes(body, "context_management", []byte(helps.ClaudeCodeContextManagementJSON))
	if errSet != nil {
		return body
	}
	return updated
}

func ensureClaudeCodeToolsArray(body []byte) []byte {
	if gjson.GetBytes(body, "tools").Exists() {
		return body
	}
	updated, errSet := sjson.SetRawBytes(body, "tools", []byte(`[]`))
	if errSet != nil {
		return body
	}
	return updated
}

type compositeReadCloser struct {
	io.Reader
	closers []func() error
}

func (c *compositeReadCloser) Close() error {
	var firstErr error
	for i := range c.closers {
		if c.closers[i] == nil {
			continue
		}
		if err := c.closers[i](); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// peekableBody wraps a bufio.Reader around the original ReadCloser so that
// magic bytes can be inspected without consuming them from the stream.
type peekableBody struct {
	*bufio.Reader
	closer io.Closer
}

func (p *peekableBody) Close() error {
	return p.closer.Close()
}

func decodeResponseBody(body io.ReadCloser, contentEncoding string) (io.ReadCloser, error) {
	if body == nil {
		return nil, fmt.Errorf("response body is nil")
	}
	if contentEncoding == "" {
		// No Content-Encoding header.  Attempt best-effort magic-byte detection to
		// handle misbehaving upstreams that compress without setting the header.
		// Only gzip (1f 8b) and zstd (28 b5 2f fd) have reliable magic sequences;
		// br and deflate have none and are left as-is.
		// The bufio wrapper preserves unread bytes so callers always see the full
		// stream regardless of whether decompression was applied.
		pb := &peekableBody{Reader: bufio.NewReader(body), closer: body}
		magic, peekErr := pb.Peek(4)
		if peekErr == nil || (peekErr == io.EOF && len(magic) >= 2) {
			switch {
			case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
				gzipReader, gzErr := gzip.NewReader(pb)
				if gzErr != nil {
					_ = pb.Close()
					return nil, fmt.Errorf("magic-byte gzip: failed to create reader: %w", gzErr)
				}
				return &compositeReadCloser{
					Reader: gzipReader,
					closers: []func() error{
						gzipReader.Close,
						pb.Close,
					},
				}, nil
			case len(magic) >= 4 && magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd:
				decoder, zdErr := zstd.NewReader(pb)
				if zdErr != nil {
					_ = pb.Close()
					return nil, fmt.Errorf("magic-byte zstd: failed to create reader: %w", zdErr)
				}
				return &compositeReadCloser{
					Reader: decoder,
					closers: []func() error{
						func() error { decoder.Close(); return nil },
						pb.Close,
					},
				}, nil
			}
		}
		return pb, nil
	}
	encodings := strings.Split(contentEncoding, ",")
	for _, raw := range encodings {
		encoding := strings.TrimSpace(strings.ToLower(raw))
		switch encoding {
		case "", "identity":
			continue
		case "gzip":
			gzipReader, err := gzip.NewReader(body)
			if err != nil {
				_ = body.Close()
				return nil, fmt.Errorf("failed to create gzip reader: %w", err)
			}
			return &compositeReadCloser{
				Reader: gzipReader,
				closers: []func() error{
					gzipReader.Close,
					func() error { return body.Close() },
				},
			}, nil
		case "deflate":
			deflateReader := flate.NewReader(body)
			return &compositeReadCloser{
				Reader: deflateReader,
				closers: []func() error{
					deflateReader.Close,
					func() error { return body.Close() },
				},
			}, nil
		case "br":
			return &compositeReadCloser{
				Reader: brotli.NewReader(body),
				closers: []func() error{
					func() error { return body.Close() },
				},
			}, nil
		case "zstd":
			decoder, err := zstd.NewReader(body)
			if err != nil {
				_ = body.Close()
				return nil, fmt.Errorf("failed to create zstd reader: %w", err)
			}
			return &compositeReadCloser{
				Reader: decoder,
				closers: []func() error{
					func() error { decoder.Close(); return nil },
					func() error { return body.Close() },
				},
			}, nil
		default:
			continue
		}
	}
	return body, nil
}

func applyClaudeHeaders(r *http.Request, auth *cliproxyauth.Auth, apiKey string, stream bool, extraBetas []string, cfg *config.Config, incomingHeaders http.Header) error {
	return applyClaudeHeadersForBody(r, auth, apiKey, stream, extraBetas, cfg, incomingHeaders, nil)
}

func applyClaudeHeadersForBody(r *http.Request, auth *cliproxyauth.Auth, apiKey string, stream bool, extraBetas []string, cfg *config.Config, incomingHeaders http.Header, body []byte) error {
	return applyClaudeHeadersForBodyAndModel(r, auth, apiKey, stream, extraBetas, cfg, incomingHeaders, body, "")
}

func applyClaudeHeadersForBodyAndModel(r *http.Request, auth *cliproxyauth.Auth, apiKey string, stream bool, extraBetas []string, cfg *config.Config, incomingHeaders http.Header, body []byte, requestedModel string) error {
	if r == nil {
		return fmt.Errorf("claude executor: request is nil")
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return fmt.Errorf("claude executor: credential is empty")
	}
	hdrDefault := func(cfgVal, fallback string) string {
		if cfgVal != "" {
			return cfgVal
		}
		return fallback
	}

	var hd config.ClaudeHeaderDefaults
	if cfg != nil {
		hd = cfg.ClaudeHeaderDefaults
	}

	useAPIKey := auth != nil && auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != ""
	oauthMode := isClaudeOAuthAuth(auth, apiKey)
	isAnthropicBase := helps.IsClaudeFirstPartyAPIURL(r.URL)
	if isAnthropicBase && useAPIKey {
		r.Header.Del("Authorization")
		r.Header.Set("x-api-key", apiKey)
	} else {
		r.Header.Set("Authorization", "Bearer "+apiKey)
	}
	r.Header.Set("Content-Type", "application/json")

	if incomingHeaders == nil {
		if ginCtx, ok := r.Context().Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
			incomingHeaders = ginCtx.Request.Header
		}
	}
	syntheticSDKClient := oauthMode && isAnthropicBase && !helps.IsClaudeCodeClientUserAgent(incomingHeaders.Get("User-Agent"))
	cloakEnabled, cloakDecided := claudeCloakDecisionFromContext(r.Context())
	if cloakDecided {
		syntheticSDKClient = syntheticSDKClient && cloakEnabled
	}
	passthroughClientIdentity := oauthMode && isAnthropicBase && cloakDecided && !cloakEnabled
	oauthProfile := helps.OfficialClaudeCodeOAuthProfile()
	stabilizeDeviceProfile := helps.ClaudeDeviceProfileStabilizationEnabled(cfg)
	var deviceProfile helps.ClaudeDeviceProfile
	if stabilizeDeviceProfile && !passthroughClientIdentity {
		var errDeviceProfile error
		deviceProfile, errDeviceProfile = helps.ResolveClaudeDeviceProfileRequired(r.Context(), auth, apiKey, incomingHeaders, cfg)
		if errDeviceProfile != nil {
			return errDeviceProfile
		}
	}

	requestBetas := append([]string(nil), extraBetas...)
	if syntheticSDKClient {
		requestBetas = append(requestBetas, helps.ClaudeCodeExtendedCacheTTLBeta)
	}
	if strings.HasSuffix(strings.TrimRight(r.URL.Path, "/"), "/v1/messages/count_tokens") {
		requestBetas = append(requestBetas, "token-counting-2024-11-01")
	}
	baselineBetas := defaultClaudeCodeBetas
	if oauthMode && isAnthropicBase {
		baselineBetas = ""
		if syntheticSDKClient {
			model := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "model").String()))
			baselineBetas = claudeCodeOAuthBetaHeaderForModel(model, requestedModel)
			if claudeCodeModelMatches(model, "claude-haiku-4-5") {
				baselineBetas = helps.ClaudeCodeHaiku45OAuthBetaHeader
			}
			if claudeCodeMidConversationSystemEnabled(model) {
				baselineBetas += "," + helps.ClaudeCodeMidConversationSystemBeta
			}
		}
	}
	setClaudeBetaHeader(r.Header, mergeClaudeBetas(incomingHeaders, requestBetas, baselineBetas))

	misc.EnsureHeader(r.Header, incomingHeaders, "Anthropic-Version", "2023-06-01")
	if oauthMode && isAnthropicBase {
		r.Header.Set(helps.ClaudeCodeDangerousDirectBrowserAccessHeader, helps.ClaudeCodeDangerousDirectBrowserAccessValue)
	} else if useAPIKey {
		misc.EnsureHeader(r.Header, incomingHeaders, helps.ClaudeCodeDangerousDirectBrowserAccessHeader, helps.ClaudeCodeDangerousDirectBrowserAccessValue)
	}
	misc.EnsureHeader(r.Header, incomingHeaders, "X-App", "cli")
	// Values below match Claude Code 2.1.216 / @anthropic-ai/sdk 0.94.0 (verified 2026-07-21).
	misc.EnsureHeader(r.Header, incomingHeaders, "X-Stainless-Retry-Count", "0")
	misc.EnsureHeader(r.Header, incomingHeaders, "X-Stainless-Runtime", "node")
	misc.EnsureHeader(r.Header, incomingHeaders, "X-Stainless-Lang", "js")
	misc.EnsureHeader(r.Header, incomingHeaders, "X-Stainless-Timeout", hdrDefault(hd.Timeout, "600"))
	// Resolve the session once per request. Cloaked payload metadata and this
	// header consume the same value, so payload overrides cannot split identity.
	sessionID := claudeCanonicalSessionIDFromContext(r.Context())
	if sessionID == "" {
		sessionID = helps.ResolveClaudeCodeSession(r.Context(), nil, incomingHeaders).SessionID
	}
	if sessionID == "" {
		scope := claudeSyntheticSessionScope(r.Context(), incomingHeaders, nil, nil)
		var errSessionID error
		if scope != "" {
			sessionID, errSessionID = helps.CachedSessionIDRequired(r.Context(), scope)
		} else {
			sessionID, errSessionID = helps.GenerateClaudeCodeSessionIDRequired()
		}
		if errSessionID != nil {
			return errSessionID
		}
	}
	r.Header.Set(helps.ClaudeCodeSessionHeader, sessionID)
	r.Header.Set("Connection", "keep-alive")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	// Legacy mode keeps OS/Arch runtime-derived; stabilized mode pins OS/Arch
	// to the configured baseline while still allowing newer official
	// User-Agent/package/runtime tuples to upgrade the software fingerprint.
	if passthroughClientIdentity {
		for _, headerName := range []string{
			"User-Agent",
			"X-Stainless-Package-Version",
			"X-Stainless-Runtime-Version",
			"X-Stainless-Os",
			"X-Stainless-Arch",
		} {
			if value := strings.TrimSpace(incomingHeaders.Get(headerName)); value != "" {
				r.Header.Set(headerName, value)
			} else {
				r.Header.Del(headerName)
			}
		}
	} else if stabilizeDeviceProfile {
		helps.ApplyClaudeDeviceProfileHeaders(r, deviceProfile)
	} else {
		helps.ApplyClaudeLegacyDeviceHeaders(r, incomingHeaders, cfg)
	}
	if syntheticSDKClient {
		r.Header.Set("User-Agent", oauthProfile.UserAgent)
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(r, attrs)
	// Identity consistency is an invariant, not a configurable header override.
	r.Header.Set(helps.ClaudeCodeSessionHeader, sessionID)
	if oauthMode && isAnthropicBase {
		r.Header.Set("Authorization", "Bearer "+apiKey)
		r.Header.Del("x-api-key")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(helps.ClaudeCodeDangerousDirectBrowserAccessHeader, helps.ClaudeCodeDangerousDirectBrowserAccessValue)
	}
	if syntheticSDKClient {
		setClaudeBetaHeader(r.Header, mergeClaudeBetas(incomingHeaders, requestBetas, baselineBetas))
		r.Header.Set("User-Agent", oauthProfile.UserAgent)
		r.Header.Set("Anthropic-Version", "2023-06-01")
		r.Header.Set("X-App", "cli")
		r.Header.Set("X-Stainless-Retry-Count", "0")
		r.Header.Set("X-Stainless-Runtime", "node")
		r.Header.Set("X-Stainless-Lang", "js")
		r.Header.Set("X-Stainless-Package-Version", hdrDefault(hd.PackageVersion, oauthProfile.SDKVersion))
		r.Header.Set("X-Stainless-Runtime-Version", hdrDefault(hd.RuntimeVersion, oauthProfile.RuntimeVersion))
		r.Header.Set("X-Stainless-Os", hdrDefault(hd.OS, oauthProfile.OS))
		r.Header.Set("X-Stainless-Arch", hdrDefault(hd.Arch, oauthProfile.Arch))
		r.Header.Set("X-Stainless-Timeout", hdrDefault(hd.Timeout, oauthProfile.Timeout))
		requestID, errRequestID := helps.GenerateClaudeCodeSessionIDRequired()
		if errRequestID != nil {
			return errRequestID
		}
		r.Header.Set("x-client-request-id", requestID)
	} else if isAnthropicBase {
		if incomingRequestID := strings.TrimSpace(incomingHeaders.Get("x-client-request-id")); incomingRequestID != "" {
			r.Header.Set("x-client-request-id", incomingRequestID)
		} else if strings.TrimSpace(r.Header.Get("x-client-request-id")) == "" {
			requestID, errRequestID := helps.GenerateClaudeCodeSessionIDRequired()
			if errRequestID != nil {
				return errRequestID
			}
			r.Header.Set("x-client-request-id", requestID)
		}
	}
	// Claude Code sends stream:true through messages.create rather than the SDK's
	// messages.stream helper. Preserve an actual Claude client's helper header,
	// but never synthesize one for the sdk-cli cloak profile.
	if syntheticSDKClient {
		r.Header.Del("X-Stainless-Helper-Method")
	} else if helperMethod := strings.TrimSpace(incomingHeaders.Get("X-Stainless-Helper-Method")); helperMethod != "" {
		r.Header.Set("X-Stainless-Helper-Method", helperMethod)
	}
	return nil
}

const defaultClaudeCodeBetas = "claude-code-20250219,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05"

func claudeCodeOAuthBetaHeaderForModel(model, requestedModel string) string {
	header := helps.ClaudeCodeOAuthBetaHeader
	if !claudeCodeContext1MEnabled(model, requestedModel) || strings.Contains(header, helps.ClaudeCodeContext1MBeta) {
		return header
	}
	const afterOAuth = "oauth-2025-04-20,"
	if strings.Contains(header, afterOAuth) {
		return strings.Replace(header, afterOAuth, afterOAuth+helps.ClaudeCodeContext1MBeta+",", 1)
	}
	return header + "," + helps.ClaudeCodeContext1MBeta
}

func claudeCodeContext1MEnabled(model, requestedModel string) bool {
	for _, candidate := range []string{requestedModel, model} {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if strings.HasSuffix(candidate, "[1m]") || strings.Contains(candidate, "[1m](") {
			return true
		}
	}
	return false
}

func mergeClaudeBetas(incomingHeaders http.Header, extraBetas []string, baseline string) string {
	var merged []string
	seen := make(map[string]bool)
	add := func(values ...string) {
		for _, value := range values {
			for _, beta := range strings.Split(value, ",") {
				beta = strings.TrimSpace(beta)
				if beta == "" || seen[beta] {
					continue
				}
				seen[beta] = true
				merged = append(merged, beta)
			}
		}
	}

	add(baseline)
	if incomingHeaders != nil {
		add(incomingHeaders.Values("Anthropic-Beta")...)
	}
	add(extraBetas...)
	return strings.Join(merged, ",")
}

func setClaudeBetaHeader(headers http.Header, value string) {
	if value = strings.TrimSpace(value); value != "" {
		headers.Set("Anthropic-Beta", value)
		return
	}
	headers.Del("Anthropic-Beta")
}

func claudeCreds(a *cliproxyauth.Auth) (apiKey, baseURL string) {
	if a == nil {
		return "", ""
	}
	if a.Attributes != nil {
		apiKey = a.Attributes["api_key"]
		baseURL = a.Attributes["base_url"]
	}
	if apiKey == "" && a.Metadata != nil {
		if v, ok := a.Metadata["access_token"].(string); ok {
			apiKey = v
		}
	}
	return
}

func checkSystemInstructions(payload []byte) []byte {
	return checkSystemInstructionsWithSigningMode(payload, false, false, false, helps.DefaultClaudeVersion(nil), "", "")
}

func rebuildMidSystemMessagesToTopLevel(payload []byte) []byte {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.IsArray() {
		return payload
	}

	var movedSystemParts []string
	keptMessages := make([]string, 0, int(messages.Get("#").Int()))
	messages.ForEach(func(_, message gjson.Result) bool {
		if strings.EqualFold(strings.TrimSpace(message.Get("role").String()), "system") {
			movedSystemParts = append(movedSystemParts, claudeSystemTextParts(message.Get("content"))...)
			return true
		}
		keptMessages = append(keptMessages, message.Raw)
		return true
	})
	if len(movedSystemParts) == 0 {
		return payload
	}

	systemParts := claudeSystemTextParts(gjson.GetBytes(payload, "system"))
	systemParts = append(systemParts, movedSystemParts...)
	if len(systemParts) > 0 {
		if updated, errSetSystem := sjson.SetRawBytes(payload, "system", rawJSONArray(systemParts)); errSetSystem == nil {
			payload = updated
		}
	}
	if updated, errSetMessages := sjson.SetRawBytes(payload, "messages", rawJSONArray(keptMessages)); errSetMessages == nil {
		payload = updated
	}
	return payload
}

func claudeSystemTextParts(content gjson.Result) []string {
	if !content.Exists() {
		return nil
	}
	if content.Type == gjson.String {
		text := content.String()
		if strings.TrimSpace(text) == "" {
			return nil
		}
		block := []byte(`{"type":"text","text":""}`)
		block, _ = sjson.SetBytes(block, "text", text)
		return []string{string(block)}
	}
	if !content.IsArray() {
		return nil
	}

	var parts []string
	content.ForEach(func(_, item gjson.Result) bool {
		if item.Type == gjson.String {
			text := item.String()
			if strings.TrimSpace(text) != "" {
				block := []byte(`{"type":"text","text":""}`)
				block, _ = sjson.SetBytes(block, "text", text)
				parts = append(parts, string(block))
			}
			return true
		}
		if item.IsObject() && item.Get("type").String() == "text" && strings.TrimSpace(item.Get("text").String()) != "" {
			parts = append(parts, item.Raw)
		}
		return true
	})
	return parts
}

func rawJSONArray(items []string) []byte {
	if len(items) == 0 {
		return []byte("[]")
	}
	var builder strings.Builder
	builder.WriteByte('[')
	for i, item := range items {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(item)
	}
	builder.WriteByte(']')
	return []byte(builder.String())
}

func canonicalizeSyntheticClaudeCodeBodyOrder(body []byte) []byte {
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		return body
	}

	values := make(map[string]string)
	inputOrder := make([]string, 0, len(root.Map()))
	root.ForEach(func(key, value gjson.Result) bool {
		name := key.String()
		if _, exists := values[name]; !exists {
			inputOrder = append(inputOrder, name)
		}
		values[name] = value.Raw
		return true
	})

	prefix := []string{
		"model", "messages", "system", "tools", "tool_choice", "betas",
		"metadata", "max_tokens", "thinking",
	}
	thinkingType := strings.ToLower(strings.TrimSpace(root.Get("thinking.type").String()))
	thinkingActive := thinkingType == "enabled" || thinkingType == "adaptive"
	model := root.Get("model").String()
	// Native Claude Code creates its ordinary inactive-thinking temperature
	// before context_management. A temperature supplied through EXTRA_BODY is
	// spread later with the other custom body fields. With thinking active (or
	// on a model that has no inactive-temperature default), every retained
	// temperature necessarily came from that later spread.
	if !thinkingActive && claudeCodeUsesInactiveTemperature(model) {
		prefix = append(prefix, "temperature")
	}
	prefix = append(prefix, "context_management")
	middle := []string{"context_hint", "cache_control", "fallbacks"}
	suffix := []string{"output_config", "speed", "diagnostics", "fallback_credit_token", "stream"}
	known := make(map[string]struct{}, len(prefix)+len(middle)+len(suffix))
	for _, name := range prefix {
		known[name] = struct{}{}
	}
	for _, name := range middle {
		known[name] = struct{}{}
	}
	for _, name := range suffix {
		known[name] = struct{}{}
	}

	ordered := make([]string, 0, len(values))
	appendPresent := func(names []string) {
		for _, name := range names {
			if _, exists := values[name]; exists {
				ordered = append(ordered, name)
			}
		}
	}
	appendPresent(prefix)
	appendPresent(middle)
	for _, name := range inputOrder {
		if _, isKnown := known[name]; !isKnown {
			ordered = append(ordered, name)
		}
	}
	appendPresent(suffix)

	var output bytes.Buffer
	output.Grow(len(body))
	output.WriteByte('{')
	for index, name := range ordered {
		if index > 0 {
			output.WriteByte(',')
		}
		output.Write(marshalClaudeJSONString(name))
		output.WriteByte(':')
		var compact bytes.Buffer
		if errCompact := json.Compact(&compact, []byte(values[name])); errCompact == nil {
			output.Write(compact.Bytes())
		} else {
			output.WriteString(values[name])
		}
	}
	output.WriteByte('}')
	return output.Bytes()
}

func isClaudeOAuthToken(apiKey string) bool {
	return strings.Contains(apiKey, "sk-ant-oat")
}

func isClaudeOAuthAuth(auth *cliproxyauth.Auth, token string) bool {
	if auth != nil {
		if auth.Attributes != nil {
			if strings.TrimSpace(auth.Attributes["api_key"]) != "" {
				return false
			}
			if strings.EqualFold(strings.TrimSpace(auth.Attributes["auth_kind"]), "oauth") {
				return true
			}
			if strings.TrimSpace(auth.Attributes["access_token"]) != "" {
				return true
			}
		}
		if auth.Metadata != nil {
			if value, ok := auth.Metadata["access_token"].(string); ok && strings.TrimSpace(value) != "" {
				return true
			}
		}
	}
	return isClaudeOAuthToken(token)
}

func isClaudeFirstPartyBaseURL(baseURL string) bool {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}
	target, errParse := url.Parse(baseURL)
	return errParse == nil && helps.IsClaudeFirstPartyAPIURL(target)
}

// prepareClaudeOAuthToolNamesForUpstream applies the Claude OAuth tool-name
// transforms in the same order across request paths. Remap runs before prefixing
// so any future non-empty prefix still composes correctly with the per-request
// reverse map.
func prepareClaudeOAuthToolNamesForUpstream(body []byte, prefix string, prefixDisabled bool) ([]byte, map[string]string) {
	body, reverseMap := remapOAuthToolNames(body)
	if !prefixDisabled {
		body = applyClaudeToolPrefix(body, prefix)
	}
	return body, reverseMap
}

// restoreClaudeOAuthToolNamesFromResponse undoes the Claude OAuth tool-name
// transforms for non-stream responses in reverse order.
func restoreClaudeOAuthToolNamesFromResponse(body []byte, prefix string, prefixDisabled bool, reverseMap map[string]string) []byte {
	if !prefixDisabled {
		body = stripClaudeToolPrefixFromResponse(body, prefix)
	}
	return reverseRemapOAuthToolNames(body, reverseMap)
}

// restoreClaudeOAuthToolNamesFromStreamLine undoes the Claude OAuth tool-name
// transforms for SSE lines in reverse order.
func restoreClaudeOAuthToolNamesFromStreamLine(line []byte, prefix string, prefixDisabled bool, reverseMap map[string]string) []byte {
	if !prefixDisabled {
		line = stripClaudeToolPrefixFromStreamLine(line, prefix)
	}
	return reverseRemapOAuthToolNamesFromStreamLine(line, reverseMap)
}

// remapOAuthToolNames renames third-party tool names to Claude Code equivalents
// and removes tools without an official counterpart. This prevents Anthropic from
// fingerprinting the request as a third-party client via tool naming patterns.
//
// It operates on: tools[].name, tool_choice.name, and all tool_use/tool_reference
// references in messages. Removed tools' corresponding tool_result blocks are preserved
// (they just become orphaned, which is safe for Claude).
//
// The returned map is keyed on the upstream (TitleCase) name and maps to the
// client-supplied original name. Callers MUST pass this map to the reverse
// functions so only names the client actually caused us to rewrite are restored
// on the response. A global reverse map (the previous implementation) incorrectly
// rewrote names the client originally sent in TitleCase (e.g. `Bash`)
// when any OTHER tool in the same request triggered a forward rename (e.g.
// `glob` -> `Glob`), because the global reverse map contained `Bash` -> `bash`
// regardless of what the client originally sent.
func remapOAuthToolNames(body []byte) ([]byte, map[string]string) {
	reverseMap := make(map[string]string, len(oauthToolRenameMap))
	// A rename is only safe when its upstream spelling is not already a distinct
	// customer name anywhere in this request. Otherwise `bash` + `Bash` would
	// collapse into two `Bash` definitions and the response could not be reversed
	// unambiguously.
	originalNames := make(map[string]struct{})
	tools := gjson.GetBytes(body, "tools")
	if tools.IsArray() {
		tools.ForEach(func(_, tool gjson.Result) bool {
			if name := tool.Get("name").String(); name != "" {
				originalNames[name] = struct{}{}
			}
			return true
		})
	}
	if name := gjson.GetBytes(body, "tool_choice.name").String(); name != "" {
		originalNames[name] = struct{}{}
	}
	messages := gjson.GetBytes(body, "messages")
	if messages.IsArray() {
		messages.ForEach(func(_, msg gjson.Result) bool {
			msg.Get("content").ForEach(func(_, part gjson.Result) bool {
				for _, path := range []string{"name", "tool_name"} {
					if name := part.Get(path).String(); name != "" {
						originalNames[name] = struct{}{}
					}
				}
				part.Get("content").ForEach(func(_, nestedPart gjson.Result) bool {
					if name := nestedPart.Get("tool_name").String(); name != "" {
						originalNames[name] = struct{}{}
					}
					return true
				})
				return true
			})
			return true
		})
	}
	proposedTargetAliases := make(map[string]map[string]struct{})
	for original := range originalNames {
		if renamed, ok := oauthToolRenameMap[original]; ok && renamed != original {
			aliases := proposedTargetAliases[renamed]
			if aliases == nil {
				aliases = make(map[string]struct{})
				proposedTargetAliases[renamed] = aliases
			}
			aliases[original] = struct{}{}
		}
	}
	renameToolName := func(name string) (string, bool) {
		renamed, ok := oauthToolRenameMap[name]
		if !ok || renamed == name {
			return name, false
		}
		if _, collision := originalNames[renamed]; collision {
			return name, false
		}
		if len(proposedTargetAliases[renamed]) > 1 {
			return name, false
		}
		return renamed, true
	}
	recordRename := func(original, renamed string) {
		// Preserve the first-seen original name if the same upstream name is
		// produced from multiple call sites; they all map back identically.
		if _, exists := reverseMap[renamed]; !exists {
			reverseMap[renamed] = original
		}
	}

	// 1. Rewrite tools array in a single pass (if present).
	// IMPORTANT: do not mutate names first and then rebuild from an older gjson
	// snapshot. gjson results are snapshots of the original bytes; rebuilding from a
	// stale snapshot will preserve removals but overwrite renamed names back to their
	// original lowercase values.
	if tools.Exists() && tools.IsArray() {

		var toolsJSON strings.Builder
		toolsJSON.WriteByte('[')
		toolCount := 0
		tools.ForEach(func(_, tool gjson.Result) bool {
			// Keep Anthropic built-in tools (web_search, code_execution, etc.) unchanged.
			if tool.Get("type").Exists() && tool.Get("type").String() != "" {
				if toolCount > 0 {
					toolsJSON.WriteByte(',')
				}
				toolsJSON.WriteString(tool.Raw)
				toolCount++
				return true
			}

			name := tool.Get("name").String()
			if oauthToolsToRemove[name] {
				return true
			}

			toolJSON := tool.Raw
			if newName, ok := renameToolName(name); ok {
				updatedTool, err := sjson.Set(toolJSON, "name", newName)
				if err == nil {
					toolJSON = updatedTool
					recordRename(name, newName)
				}
			}

			if toolCount > 0 {
				toolsJSON.WriteByte(',')
			}
			toolsJSON.WriteString(toolJSON)
			toolCount++
			return true
		})
		toolsJSON.WriteByte(']')
		body, _ = sjson.SetRawBytes(body, "tools", []byte(toolsJSON.String()))
	}

	// 2. Rename tool_choice if it references a known tool
	toolChoiceType := gjson.GetBytes(body, "tool_choice.type").String()
	if toolChoiceType == "tool" {
		tcName := gjson.GetBytes(body, "tool_choice.name").String()
		if oauthToolsToRemove[tcName] {
			// The chosen tool was removed from the tools array, so drop tool_choice to
			// keep the payload internally consistent and fall back to normal auto tool use.
			body, _ = sjson.DeleteBytes(body, "tool_choice")
		} else if newName, ok := renameToolName(tcName); ok {
			body, _ = sjson.SetBytes(body, "tool_choice.name", newName)
			recordRename(tcName, newName)
		}
	}

	// 3. Rename tool references in messages
	if messages.Exists() && messages.IsArray() {
		messages.ForEach(func(msgIndex, msg gjson.Result) bool {
			content := msg.Get("content")
			if !content.Exists() || !content.IsArray() {
				return true
			}
			content.ForEach(func(contentIndex, part gjson.Result) bool {
				partType := part.Get("type").String()
				switch partType {
				case "tool_use":
					name := part.Get("name").String()
					if newName, ok := renameToolName(name); ok {
						path := fmt.Sprintf("messages.%d.content.%d.name", msgIndex.Int(), contentIndex.Int())
						body, _ = sjson.SetBytes(body, path, newName)
						recordRename(name, newName)
					}
				case "tool_reference":
					toolName := part.Get("tool_name").String()
					if newName, ok := renameToolName(toolName); ok {
						path := fmt.Sprintf("messages.%d.content.%d.tool_name", msgIndex.Int(), contentIndex.Int())
						body, _ = sjson.SetBytes(body, path, newName)
						recordRename(toolName, newName)
					}
				case "tool_result":
					// Handle nested tool_reference blocks inside tool_result.content[]
					toolID := part.Get("tool_use_id").String()
					_ = toolID // tool_use_id stays as-is
					nestedContent := part.Get("content")
					if nestedContent.Exists() && nestedContent.IsArray() {
						nestedContent.ForEach(func(nestedIndex, nestedPart gjson.Result) bool {
							if nestedPart.Get("type").String() == "tool_reference" {
								nestedToolName := nestedPart.Get("tool_name").String()
								if newName, ok := renameToolName(nestedToolName); ok {
									nestedPath := fmt.Sprintf("messages.%d.content.%d.content.%d.tool_name", msgIndex.Int(), contentIndex.Int(), nestedIndex.Int())
									body, _ = sjson.SetBytes(body, nestedPath, newName)
									recordRename(nestedToolName, newName)
								}
							}
							return true
						})
					}
				}
				return true
			})
			return true
		})
	}

	return body, reverseMap
}

// reverseRemapOAuthToolNames reverses the tool name mapping for non-stream responses
// using the per-request map produced by remapOAuthToolNames. Names the client sent
// that were NOT forward-renamed are passed through unchanged.
func reverseRemapOAuthToolNames(body []byte, reverseMap map[string]string) []byte {
	if len(reverseMap) == 0 {
		return body
	}
	content := gjson.GetBytes(body, "content")
	if !content.Exists() || !content.IsArray() {
		return body
	}
	content.ForEach(func(index, part gjson.Result) bool {
		partType := part.Get("type").String()
		switch partType {
		case "tool_use":
			name := part.Get("name").String()
			if origName, ok := reverseMap[name]; ok {
				path := fmt.Sprintf("content.%d.name", index.Int())
				body, _ = sjson.SetBytes(body, path, origName)
			}
		case "tool_reference":
			toolName := part.Get("tool_name").String()
			if origName, ok := reverseMap[toolName]; ok {
				path := fmt.Sprintf("content.%d.tool_name", index.Int())
				body, _ = sjson.SetBytes(body, path, origName)
			}
		}
		return true
	})
	return body
}

// reverseRemapOAuthToolNamesFromStreamLine reverses the tool name mapping for SSE
// stream lines, using the per-request reverseMap produced by remapOAuthToolNames.
func reverseRemapOAuthToolNamesFromStreamLine(line []byte, reverseMap map[string]string) []byte {
	if len(reverseMap) == 0 {
		return line
	}
	payload := helps.JSONPayload(line)
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return line
	}

	contentBlock := gjson.GetBytes(payload, "content_block")
	if !contentBlock.Exists() {
		return line
	}

	blockType := contentBlock.Get("type").String()
	var updated []byte
	var err error

	switch blockType {
	case "tool_use":
		name := contentBlock.Get("name").String()
		if origName, ok := reverseMap[name]; ok {
			updated, err = sjson.SetBytes(payload, "content_block.name", origName)
			if err != nil {
				return line
			}
		} else {
			return line
		}
	case "tool_reference":
		toolName := contentBlock.Get("tool_name").String()
		if origName, ok := reverseMap[toolName]; ok {
			updated, err = sjson.SetBytes(payload, "content_block.tool_name", origName)
			if err != nil {
				return line
			}
		} else {
			return line
		}
	default:
		return line
	}

	trimmed := bytes.TrimSpace(line)
	if bytes.HasPrefix(trimmed, []byte("data:")) {
		return append([]byte("data: "), updated...)
	}
	return updated
}

func applyClaudeToolPrefix(body []byte, prefix string) []byte {
	if prefix == "" {
		return body
	}

	// Collect built-in tool names from the authoritative fallback seed list and
	// augment it with any typed built-ins present in the current request body.
	builtinTools := helps.AugmentClaudeBuiltinToolRegistry(body, nil)

	if tools := gjson.GetBytes(body, "tools"); tools.Exists() && tools.IsArray() {
		tools.ForEach(func(index, tool gjson.Result) bool {
			// Skip built-in tools (web_search, code_execution, etc.) which have
			// a "type" field and require their name to remain unchanged.
			if tool.Get("type").Exists() && tool.Get("type").String() != "" {
				if n := tool.Get("name").String(); n != "" {
					builtinTools[n] = true
				}
				return true
			}
			name := tool.Get("name").String()
			if name == "" || strings.HasPrefix(name, prefix) {
				return true
			}
			path := fmt.Sprintf("tools.%d.name", index.Int())
			body, _ = sjson.SetBytes(body, path, prefix+name)
			return true
		})
	}

	if gjson.GetBytes(body, "tool_choice.type").String() == "tool" {
		name := gjson.GetBytes(body, "tool_choice.name").String()
		if name != "" && !strings.HasPrefix(name, prefix) && !builtinTools[name] {
			body, _ = sjson.SetBytes(body, "tool_choice.name", prefix+name)
		}
	}

	if messages := gjson.GetBytes(body, "messages"); messages.Exists() && messages.IsArray() {
		messages.ForEach(func(msgIndex, msg gjson.Result) bool {
			content := msg.Get("content")
			if !content.Exists() || !content.IsArray() {
				return true
			}
			content.ForEach(func(contentIndex, part gjson.Result) bool {
				partType := part.Get("type").String()
				switch partType {
				case "tool_use":
					name := part.Get("name").String()
					if name == "" || strings.HasPrefix(name, prefix) || builtinTools[name] {
						return true
					}
					path := fmt.Sprintf("messages.%d.content.%d.name", msgIndex.Int(), contentIndex.Int())
					body, _ = sjson.SetBytes(body, path, prefix+name)
				case "tool_reference":
					toolName := part.Get("tool_name").String()
					if toolName == "" || strings.HasPrefix(toolName, prefix) || builtinTools[toolName] {
						return true
					}
					path := fmt.Sprintf("messages.%d.content.%d.tool_name", msgIndex.Int(), contentIndex.Int())
					body, _ = sjson.SetBytes(body, path, prefix+toolName)
				case "tool_result":
					// Handle nested tool_reference blocks inside tool_result.content[]
					nestedContent := part.Get("content")
					if nestedContent.Exists() && nestedContent.IsArray() {
						nestedContent.ForEach(func(nestedIndex, nestedPart gjson.Result) bool {
							if nestedPart.Get("type").String() == "tool_reference" {
								nestedToolName := nestedPart.Get("tool_name").String()
								if nestedToolName != "" && !strings.HasPrefix(nestedToolName, prefix) && !builtinTools[nestedToolName] {
									nestedPath := fmt.Sprintf("messages.%d.content.%d.content.%d.tool_name", msgIndex.Int(), contentIndex.Int(), nestedIndex.Int())
									body, _ = sjson.SetBytes(body, nestedPath, prefix+nestedToolName)
								}
							}
							return true
						})
					}
				}
				return true
			})
			return true
		})
	}

	return body
}

func stripClaudeToolPrefixFromResponse(body []byte, prefix string) []byte {
	if prefix == "" {
		return body
	}
	content := gjson.GetBytes(body, "content")
	if !content.Exists() || !content.IsArray() {
		return body
	}
	content.ForEach(func(index, part gjson.Result) bool {
		partType := part.Get("type").String()
		switch partType {
		case "tool_use":
			name := part.Get("name").String()
			if !strings.HasPrefix(name, prefix) {
				return true
			}
			path := fmt.Sprintf("content.%d.name", index.Int())
			body, _ = sjson.SetBytes(body, path, strings.TrimPrefix(name, prefix))
		case "tool_reference":
			toolName := part.Get("tool_name").String()
			if !strings.HasPrefix(toolName, prefix) {
				return true
			}
			path := fmt.Sprintf("content.%d.tool_name", index.Int())
			body, _ = sjson.SetBytes(body, path, strings.TrimPrefix(toolName, prefix))
		case "tool_result":
			// Handle nested tool_reference blocks inside tool_result.content[]
			nestedContent := part.Get("content")
			if nestedContent.Exists() && nestedContent.IsArray() {
				nestedContent.ForEach(func(nestedIndex, nestedPart gjson.Result) bool {
					if nestedPart.Get("type").String() == "tool_reference" {
						nestedToolName := nestedPart.Get("tool_name").String()
						if strings.HasPrefix(nestedToolName, prefix) {
							nestedPath := fmt.Sprintf("content.%d.content.%d.tool_name", index.Int(), nestedIndex.Int())
							body, _ = sjson.SetBytes(body, nestedPath, strings.TrimPrefix(nestedToolName, prefix))
						}
					}
					return true
				})
			}
		}
		return true
	})
	return body
}

func stripClaudeToolPrefixFromStreamLine(line []byte, prefix string) []byte {
	if prefix == "" {
		return line
	}
	payload := helps.JSONPayload(line)
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return line
	}
	contentBlock := gjson.GetBytes(payload, "content_block")
	if !contentBlock.Exists() {
		return line
	}

	blockType := contentBlock.Get("type").String()
	var updated []byte
	var err error

	switch blockType {
	case "tool_use":
		name := contentBlock.Get("name").String()
		if !strings.HasPrefix(name, prefix) {
			return line
		}
		updated, err = sjson.SetBytes(payload, "content_block.name", strings.TrimPrefix(name, prefix))
		if err != nil {
			return line
		}
	case "tool_reference":
		toolName := contentBlock.Get("tool_name").String()
		if !strings.HasPrefix(toolName, prefix) {
			return line
		}
		updated, err = sjson.SetBytes(payload, "content_block.tool_name", strings.TrimPrefix(toolName, prefix))
		if err != nil {
			return line
		}
	default:
		return line
	}

	trimmed := bytes.TrimSpace(line)
	if bytes.HasPrefix(trimmed, []byte("data:")) {
		return append([]byte("data: "), updated...)
	}
	return updated
}

type claudeClientHeadersContextKey struct{}

// resolveClaudeClientContext merges the executor's forwarded headers over the
// inbound HTTP headers once. Body cloaking and upstream header shaping then
// consume the same client profile, including SDK calls without a gin context.
func resolveClaudeClientContext(ctx context.Context, forwarded http.Header) (context.Context, http.Header) {
	if ctx == nil {
		ctx = context.Background()
	}
	merged := make(http.Header)
	if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		merged = canonicalClaudeClientHeaders(ginCtx.Request.Header)
	}
	for key, values := range canonicalClaudeClientHeaders(forwarded) {
		merged[key] = append([]string(nil), values...)
	}
	ctx = context.WithValue(ctx, claudeClientHeadersContextKey{}, merged.Clone())
	return ctx, merged
}

func canonicalClaudeClientHeaders(headers http.Header) http.Header {
	canonical := make(http.Header)
	if headers == nil {
		return canonical
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		canonicalKey := http.CanonicalHeaderKey(key)
		canonical[canonicalKey] = append(canonical[canonicalKey], headers[key]...)
	}
	return canonical
}

func claudeClientHeadersFromContext(ctx context.Context) http.Header {
	if ctx == nil {
		return nil
	}
	headers, _ := ctx.Value(claudeClientHeadersContextKey{}).(http.Header)
	return headers
}

// getClientUserAgent extracts the canonical downstream client User-Agent.
func getClientUserAgent(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if headers := claudeClientHeadersFromContext(ctx); headers != nil {
		return strings.TrimSpace(headers.Get("User-Agent"))
	}
	if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		return strings.TrimSpace(ginCtx.GetHeader("User-Agent"))
	}
	return ""
}

type claudeCanonicalSessionContextKey struct{}

const claudeProxyInstallationIdentityScope = "claude-code-sdk-cli-installation-v1"

func withClaudeCanonicalSessionID(ctx context.Context, sessionID string) context.Context {
	updated, err := withClaudeCanonicalSessionIDRequired(ctx, sessionID)
	if err != nil {
		return ctx
	}
	return updated
}

func withClaudeCanonicalSessionIDRequired(ctx context.Context, sessionID string) (context.Context, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	sessionID = strings.TrimSpace(sessionID)
	if !helps.IsValidClaudeCodeUUID(sessionID) {
		return nil, fmt.Errorf("invalid canonical Claude Code session UUID")
	}
	return context.WithValue(ctx, claudeCanonicalSessionContextKey{}, sessionID), nil
}

func claudeCanonicalSessionIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	sessionID, _ := ctx.Value(claudeCanonicalSessionContextKey{}).(string)
	sessionID = strings.TrimSpace(sessionID)
	if !helps.IsValidClaudeCodeUUID(sessionID) {
		return ""
	}
	return sessionID
}

func claudeSyntheticSessionScope(ctx context.Context, headers http.Header, payload []byte, metadata map[string]any) string {
	namespace := claudeDownstreamSessionNamespace(ctx, headers)
	if executionSessionID := metadataString(metadata, cliproxyexecutor.ExecutionSessionMetadataKey); executionSessionID != "" {
		return namespaceClaudeSessionScope(namespace, "execution:"+executionSessionID, false)
	}
	if legacySessionID := helps.ExtractClaudeCodeSessionID(ctx, payload, headers); legacySessionID != "" {
		return namespaceClaudeSessionScope(namespace, "legacy-claude:"+legacySessionID, false)
	}
	stableHeaders := canonicalClaudeClientHeaders(headers)
	stableHeaders.Del("X-Client-Request-Id")
	scope := cliproxyauth.ExtractStableSessionID(stableHeaders, payload, metadata)
	return namespaceClaudeSessionScope(namespace, scope, strings.HasPrefix(scope, "msg:"))
}

func namespaceClaudeSessionScope(namespace, scope string, requireNamespace bool) string {
	scope = strings.TrimSpace(scope)
	if scope == "" || (requireNamespace && namespace == "") {
		return ""
	}
	if namespace == "" {
		return scope
	}
	return "principal:" + namespace + ":" + scope
}

func claudeDownstreamSessionNamespace(ctx context.Context, headers http.Header) string {
	var principal string
	if ctx != nil {
		if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil {
			if value, exists := ginCtx.Get("userApiKey"); exists {
				principal = strings.TrimSpace(fmt.Sprint(value))
			}
			if principal == "" && ginCtx.Request != nil {
				principal = strings.TrimSpace(ginCtx.ClientIP())
			}
		}
	}
	if principal == "" {
		for _, name := range []string{"X-Api-Key", "Authorization", "Proxy-Authorization"} {
			if value := strings.TrimSpace(headers.Get(name)); value != "" {
				principal = value
				break
			}
		}
	}
	if principal == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(principal))
	return hex.EncodeToString(digest[:])
}

func resolveClaudeCanonicalSessionIDRequired(
	ctx context.Context,
	translatedPayload []byte,
	originalPayload []byte,
	headers http.Header,
	metadata ...map[string]any,
) (string, error) {
	translatedResolution := helps.ResolveClaudeCodeSession(ctx, translatedPayload, headers)
	originalResolution := helps.ResolveClaudeCodeSession(ctx, originalPayload, headers)
	conflict := translatedResolution.Conflict || originalResolution.Conflict
	if translatedResolution.SessionID != "" && originalResolution.SessionID != "" && translatedResolution.SessionID != originalResolution.SessionID {
		conflict = true
	}
	if helps.IsClaudeCodeClientUserAgent(getClientUserAgent(ctx)) {
		if translatedResolution.InvalidHeader || originalResolution.InvalidHeader || translatedResolution.InvalidPayload || originalResolution.InvalidPayload {
			return "", fmt.Errorf("invalid Claude Code session identity in request")
		}
		if conflict {
			return "", fmt.Errorf("conflicting Claude Code session UUIDs in request header and metadata")
		}
	}
	if translatedResolution.SessionID != "" {
		return translatedResolution.SessionID, nil
	}
	if originalResolution.SessionID != "" {
		return originalResolution.SessionID, nil
	}
	for _, values := range metadata {
		if executionSessionID := metadataString(values, cliproxyexecutor.ExecutionSessionMetadataKey); executionSessionID != "" {
			scope := namespaceClaudeSessionScope(claudeDownstreamSessionNamespace(ctx, headers), "execution:"+executionSessionID, false)
			return helps.CachedSessionIDRequired(ctx, "downstream:"+scope)
		}
	}
	if scope := claudeSyntheticSessionScope(ctx, headers, originalPayload, nil); scope != "" {
		return helps.CachedSessionIDRequired(ctx, "downstream:"+scope)
	}
	if scope := claudeSyntheticSessionScope(ctx, headers, translatedPayload, nil); scope != "" {
		return helps.CachedSessionIDRequired(ctx, "downstream:"+scope)
	}
	return helps.GenerateClaudeCodeSessionIDRequired()
}

// parseEntrypointFromUA extracts the entrypoint from a Claude Code User-Agent.
// Format: "claude-cli/x.y.z (external, cli)" → "cli"
// Format: "claude-cli/x.y.z (external, vscode)" → "vscode"
// Returns "sdk-cli" if parsing fails or UA is not Claude Code. Cloaked
// third-party clients use the Agent SDK entrypoint in Claude Code 2.1.216.
func parseEntrypointFromUA(userAgent string) string {
	if !helps.IsClaudeCodeClientUserAgent(userAgent) {
		return "sdk-cli"
	}
	// Find content inside parentheses
	start := strings.Index(userAgent, "(")
	end := strings.LastIndex(userAgent, ")")
	if start < 0 || end <= start {
		return "sdk-cli"
	}
	inner := userAgent[start+1 : end]
	// Split by comma, take the second part (entrypoint is at index 1, after USER_TYPE)
	// Format: "(USER_TYPE, ENTRYPOINT[, extra...])"
	parts := strings.Split(inner, ",")
	if len(parts) >= 2 {
		ep := strings.TrimSpace(parts[1])
		if ep != "" && len(ep) <= 32 {
			valid := true
			for index := 0; index < len(ep); index++ {
				char := ep[index]
				if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
					continue
				}
				valid = false
				break
			}
			if valid {
				return ep
			}
		}
	}
	return "sdk-cli"
}

// getWorkloadFromContext extracts workload identifier from the gin request headers.
func getWorkloadFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if headers := claudeClientHeadersFromContext(ctx); headers != nil {
		return validClaudeControlRequestID(headers.Get("X-CPA-Claude-Workload"))
	}
	if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		return validClaudeControlRequestID(ginCtx.GetHeader("X-CPA-Claude-Workload"))
	}
	return ""
}

func claudePreviousRequestScope(ctx context.Context, auth *cliproxyauth.Auth) string {
	sessionID := claudeCanonicalSessionIDFromContext(ctx)
	if sessionID == "" {
		return ""
	}
	namespace := claudeDownstreamSessionNamespace(ctx, claudeClientHeadersFromContext(ctx))
	credentialScope := ""
	if accountUUID, errAccountUUID := claudeOAuthAccountUUID(auth); errAccountUUID == nil {
		credentialScope = accountUUID
	}
	if credentialScope == "" && auth != nil {
		credentialScope = strings.TrimSpace(auth.ID)
	}
	if namespace == "" && credentialScope == "" {
		return sessionID
	}
	return namespace + "\x00" + credentialScope + "\x00" + sessionID
}

// validClaudeControlRequestID applies a conservative grammar to CPA-specific
// downstream controls. Claude Code itself does not impose this grammar on the
// trusted request-id response header.
func validClaudeControlRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-' {
			continue
		}
		return ""
	}
	return value
}

func claudeHeaderValue(headers http.Header, name string) (string, bool) {
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		if len(values) == 0 {
			return "", true
		}
		return strings.TrimSpace(values[0]), true
	}
	return "", false
}

func loadClaudePreviousRequest(scope string) string {
	if scope == "" {
		return ""
	}
	now := time.Now()
	claudePreviousRequestsMu.Lock()
	defer claudePreviousRequestsMu.Unlock()
	entry, exists := claudePreviousRequests[scope]
	if !exists {
		return ""
	}
	if !entry.expiresAt.After(now) || validClaudeControlRequestID(entry.requestID) == "" {
		delete(claudePreviousRequests, scope)
		return ""
	}
	return entry.requestID
}

func storeClaudePreviousRequest(scope, requestID string) {
	requestID = validClaudeControlRequestID(requestID)
	if scope == "" || requestID == "" {
		return
	}
	now := time.Now()
	claudePreviousRequestsMu.Lock()
	defer claudePreviousRequestsMu.Unlock()
	if len(claudePreviousRequests) >= claudePreviousRequestMax {
		oldestScope := ""
		var oldestExpiry time.Time
		for candidateScope, entry := range claudePreviousRequests {
			if !entry.expiresAt.After(now) {
				delete(claudePreviousRequests, candidateScope)
				continue
			}
			if oldestScope == "" || entry.expiresAt.Before(oldestExpiry) {
				oldestScope = candidateScope
				oldestExpiry = entry.expiresAt
			}
		}
		if len(claudePreviousRequests) >= claudePreviousRequestMax && oldestScope != "" {
			delete(claudePreviousRequests, oldestScope)
		}
	}
	claudePreviousRequests[scope] = claudePreviousRequestEntry{
		requestID: requestID,
		expiresAt: now.Add(claudePreviousRequestTTL),
	}
}

// claudeAssistantPreviousRequest returns direct transcript evidence. An
// explicitly present but malformed latest requestId blocks older/cache data.
func claudeAssistantPreviousRequest(payload []byte) (requestID string, explicit bool) {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.IsArray() {
		return "", false
	}
	items := messages.Array()
	for index := len(items) - 1; index >= 0; index-- {
		message := items[index]
		if message.Get("role").String() != "assistant" {
			continue
		}
		requestIDValue := message.Get("requestId")
		if !requestIDValue.Exists() {
			requestIDValue = message.Get("_request_id")
			if !requestIDValue.Exists() {
				continue
			}
		}
		if requestIDValue.Type != gjson.String {
			return "", true
		}
		return validClaudeControlRequestID(requestIDValue.String()), true
	}
	return "", false
}

func stripClaudeAssistantRequestIDs(payload []byte) []byte {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.IsArray() {
		return payload
	}
	for index := range messages.Array() {
		for _, field := range []string{"requestId", "_request_id"} {
			path := fmt.Sprintf("messages.%d.%s", index, field)
			if !gjson.GetBytes(payload, path).Exists() {
				continue
			}
			if updated, errDelete := sjson.DeleteBytes(payload, path); errDelete == nil {
				payload = updated
			}
		}
	}
	return payload
}

// applySyntheticClaudeBillingAttribution adds only attribution for which the
// proxy has explicit evidence. In particular, parent_session_id alone is not a
// subagent signal in Claude Code 2.1.216.
func applySyntheticClaudeBillingAttribution(ctx context.Context, payload []byte, previousRequestScope string) []byte {
	headers := claudeClientHeadersFromContext(ctx)
	previousRequestID := ""
	if headerValue, headerPresent := claudeHeaderValue(headers, claudePrevRequestHeader); headerPresent {
		previousRequestID = validClaudeControlRequestID(headerValue)
	} else if transcriptRequestID, transcriptExplicit := claudeAssistantPreviousRequest(payload); transcriptExplicit {
		previousRequestID = transcriptRequestID
	} else {
		previousRequestID = loadClaudePreviousRequest(previousRequestScope)
	}

	// requestId is a Claude Code transcript-envelope field, not a Messages API
	// request field. _request_id is stripped as a legacy CPA extension too.
	payload = stripClaudeAssistantRequestIDs(payload)
	billingPath := "system.0.text"
	billing := gjson.GetBytes(payload, billingPath)
	if billing.Type != gjson.String || !strings.HasPrefix(billing.String(), "x-anthropic-billing-header:") {
		return payload
	}
	updatedBilling := billing.String()
	if subagentValue, exists := claudeHeaderValue(headers, claudeSyntheticSubagentHeader); exists && strings.EqualFold(subagentValue, "true") {
		updatedBilling += " cc_is_subagent=true;"
	}
	if previousRequestID != "" {
		updatedBilling += " cc_prev_req=" + previousRequestID + ";"
	}
	if updatedBilling == billing.String() {
		return payload
	}
	updated, errSet := sjson.SetBytes(payload, billingPath, updatedBilling)
	if errSet != nil {
		return payload
	}
	return updated
}

// getCloakConfigFromAuth extracts cloak configuration from the auth's attributes,
// falling back to its stored metadata (the raw OAuth/token JSON). Returns
// (cloakMode, strictMode, sensitiveWords, cacheUserID, fullSystemPrompt); an empty
// cloakMode means the credential did not explicitly configure a mode.
func getCloakConfigFromAuth(auth *cliproxyauth.Auth) (cloakMode string, strictMode bool, sensitiveWords []string, cacheUserID *bool, fullSystemPrompt *bool) {
	if auth == nil {
		return "", false, nil, nil, nil
	}

	// lookupCloakAttr prefers the executor-facing Attributes, then falls back to the
	// raw metadata blob (e.g. the OAuth/token JSON) so file-based credentials can
	// carry cloak settings without a matching claude-api-key config entry.
	lookupCloakAttr := func(key string) string {
		if auth.Attributes != nil {
			if value := strings.TrimSpace(auth.Attributes[key]); value != "" {
				return value
			}
		}
		if auth.Metadata != nil {
			if value, ok := auth.Metadata[key].(string); ok {
				return strings.TrimSpace(value)
			}
		}
		return ""
	}

	lookupCloakBoolAttr := func(key string) *bool {
		parse := func(value string) *bool {
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return nil
			}
			return &parsed
		}
		if auth.Attributes != nil {
			if value := strings.TrimSpace(auth.Attributes[key]); value != "" {
				return parse(value)
			}
		}
		if auth.Metadata != nil {
			switch value := auth.Metadata[key].(type) {
			case bool:
				parsed := value
				return &parsed
			case string:
				if strings.TrimSpace(value) != "" {
					return parse(value)
				}
			}
		}
		return nil
	}

	// An empty cloakMode means this credential did not explicitly configure a mode,
	// allowing the caller to fall back to the global/default behavior.
	cloakMode = lookupCloakAttr("cloak_mode")

	strictMode = strings.EqualFold(lookupCloakAttr("cloak_strict_mode"), "true")

	if wordsStr := lookupCloakAttr("cloak_sensitive_words"); wordsStr != "" {
		sensitiveWords = strings.Split(wordsStr, ",")
		for i := range sensitiveWords {
			sensitiveWords[i] = strings.TrimSpace(sensitiveWords[i])
		}
	}

	cacheUserID = lookupCloakBoolAttr("cloak_cache_user_id")
	fullSystemPrompt = lookupCloakBoolAttr("cloak_full_system_prompt")

	return cloakMode, strictMode, sensitiveWords, cacheUserID, fullSystemPrompt
}

func fullSystemPromptCloakEnabled(cfg *config.Config, auth *cliproxyauth.Auth) bool {
	_, _, _, _, attrFullSystemPrompt := getCloakConfigFromAuth(auth)
	fullSystemPrompt := true
	if attrFullSystemPrompt != nil {
		fullSystemPrompt = *attrFullSystemPrompt
	}
	if cloakCfg := resolveClaudeKeyCloakConfig(cfg, auth); cloakCfg != nil && cloakCfg.FullSystemPrompt != nil {
		fullSystemPrompt = *cloakCfg.FullSystemPrompt
	}
	return fullSystemPrompt
}

// injectFakeUserID emits one canonical Claude Code metadata.user_id. The
// installation-scoped device identity is independent of the rotating OAuth
// access token, while the session is resolved once and shared with the header.
func claudeOAuthAccountUUID(auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", nil
	}
	for _, key := range []string{"account_uuid", "accountUuid"} {
		if auth.Metadata != nil {
			if accountUUID := metadataString(auth.Metadata, key); accountUUID != "" {
				if !helps.IsValidClaudeCodeUUID(accountUUID) {
					return "", fmt.Errorf("invalid Claude OAuth account UUID")
				}
				return accountUUID, nil
			}
		}
		if auth.Attributes != nil {
			if accountUUID := strings.TrimSpace(auth.Attributes[key]); accountUUID != "" {
				if !helps.IsValidClaudeCodeUUID(accountUUID) {
					return "", fmt.Errorf("invalid Claude OAuth account UUID")
				}
				return accountUUID, nil
			}
		}
	}
	return "", nil
}

func validateClaudeClientOAuthAccount(ctx context.Context, auth *cliproxyauth.Auth, apiKey, baseURL string, payloads ...[]byte) error {
	if !helps.IsClaudeCodeClientUserAgent(getClientUserAgent(ctx)) ||
		!isClaudeOAuthAuth(auth, apiKey) ||
		!isClaudeFirstPartyBaseURL(baseURL) {
		return nil
	}
	expectedAccountUUID, errAccountUUID := claudeOAuthAccountUUID(auth)
	if errAccountUUID != nil || expectedAccountUUID == "" {
		return errAccountUUID
	}
	for _, payload := range payloads {
		userID := strings.TrimSpace(gjson.GetBytes(payload, "metadata.user_id").String())
		if userID == "" {
			continue
		}
		parsed, errParse := helps.ParseClaudeCodeClientUserID(userID)
		if errParse != nil {
			return fmt.Errorf("invalid Claude Code metadata.user_id")
		}
		if parsed.AccountUUID != expectedAccountUUID {
			return fmt.Errorf("Claude Code account UUID does not match selected OAuth subscription")
		}
	}
	return nil
}

func injectFakeUserID(ctx context.Context, payload []byte, identityScope, accountUUID, authDir string, useCache bool) ([]byte, error) {
	sessionID := claudeCanonicalSessionIDFromContext(ctx)
	if sessionID == "" {
		var errSessionID error
		sessionID, errSessionID = helps.CachedSessionIDRequired(ctx, identityScope)
		if errSessionID != nil {
			return nil, errSessionID
		}
	}

	deviceID, errDeviceID := helps.GenerateClaudeCodeDeviceIDRequired()
	if errDeviceID != nil {
		return nil, errDeviceID
	}
	if useCache {
		deviceID, errDeviceID = helps.CachedClaudeCodeInstallationDeviceIDRequired(ctx, identityScope, authDir)
		if errDeviceID != nil {
			return nil, errDeviceID
		}
	}

	userID, errUserID := helps.BuildClaudeCodeUserIDRequired(deviceID, accountUUID, sessionID)
	if errUserID != nil {
		return nil, errUserID
	}
	// Fit() in Claude Code constructs the top-level metadata object from scratch;
	// only its JSON-encoded user_id is sent to the Messages API. Do the same so
	// arbitrary downstream metadata keys do not survive the synthetic path.
	metadata, errMetadata := json.Marshal(struct {
		UserID string `json:"user_id"`
	}{UserID: userID})
	if errMetadata != nil {
		return nil, fmt.Errorf("encode Claude Code metadata: %w", errMetadata)
	}
	updated, errSet := sjson.SetRawBytes(payload, "metadata", metadata)
	if errSet != nil {
		return nil, fmt.Errorf("inject Claude Code user ID: %w", errSet)
	}
	return updated, nil
}

// fingerprintSalt is the salt used by Claude Code to compute the 3-char build fingerprint.
const fingerprintSalt = "59cf53e54c78"

// computeFingerprint computes the 3-char build fingerprint that Claude Code embeds in cc_version.
// Algorithm: SHA256(salt + firstUserText[4] + firstUserText[7] + firstUserText[20] + version)[:3]
func computeFingerprint(messageText, version string) string {
	indices := [3]int{4, 7, 20}
	// Claude Code runs this algorithm in JavaScript, where string indexes address
	// UTF-16 code units rather than Unicode code points. Converting first keeps
	// fingerprints identical when the leading user text contains astral symbols.
	codeUnits := utf16.Encode([]rune(messageText))
	selected := make([]uint16, 0, len(indices))
	for _, idx := range indices {
		if idx < len(codeUnits) {
			selected = append(selected, codeUnits[idx])
		} else {
			selected = append(selected, uint16('0'))
		}
	}
	// JavaScript concatenates the selected code units before UTF-8 encoding. A
	// high/low pair selected from separate positions therefore becomes one rune;
	// unpaired surrogates become U+FFFD.
	input := fingerprintSalt + string(utf16.Decode(selected)) + version
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])[:3]
}

// generateBillingHeader creates the x-anthropic-billing-header text block that
// real Claude Code prepends to every system prompt array.
// Format: x-anthropic-billing-header: cc_version=<ver>.<build>; cc_entrypoint=<ep>; [cch=<hash>;] [cc_workload=<wl>;]
func generateBillingHeader(_ []byte, cchSigning bool, version, messageText, entrypoint, workload string) string {
	if entrypoint == "" {
		entrypoint = "sdk-cli"
	}
	buildHash := computeFingerprint(messageText, version)
	cchPart := ""
	if cchSigning {
		cchPart = " cch=00000;"
	}
	workloadPart := ""
	if workload != "" {
		workloadPart = fmt.Sprintf(" cc_workload=%s;", workload)
	}
	return fmt.Sprintf("x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=%s;%s%s", version, buildHash, entrypoint, cchPart, workloadPart)
}

func checkSystemInstructionsWithMode(payload []byte, strictMode bool) []byte {
	return checkSystemInstructionsWithSigningMode(payload, strictMode, false, false, helps.DefaultClaudeVersion(nil), "", "")
}

func claudeFirstUserText(payload []byte) string {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.IsArray() {
		return ""
	}
	firstText := ""
	messages.ForEach(func(_, message gjson.Result) bool {
		if !strings.EqualFold(strings.TrimSpace(message.Get("role").String()), "user") || message.Get("isMeta").Bool() {
			return true
		}
		content := message.Get("content")
		if content.Type == gjson.String {
			firstText = content.String()
			return false
		}
		if content.IsArray() {
			fallback := ""
			content.ForEach(func(_, part gjson.Result) bool {
				if part.Get("type").String() == "text" {
					text := part.Get("text").String()
					if fallback == "" {
						fallback = text
					}
					if !isClaudeSystemReminderText(text) {
						firstText = text
						return false
					}
				}
				return true
			})
			if firstText == "" {
				firstText = fallback
			}
		}
		return false
	})
	return firstText
}

func isClaudeSystemReminderText(text string) bool {
	return strings.HasPrefix(strings.TrimSpace(text), "<system-reminder>")
}

func checkSystemInstructionsWithSigningMode(payload []byte, strictMode bool, cchSigning bool, oauthMode bool, version, entrypoint, workload string) []byte {
	return checkSystemInstructionsWithFullSystemPrompt(payload, strictMode, cchSigning, oauthMode, version, entrypoint, workload, true)
}

// checkSystemInstructionsWithFullSystemPrompt injects Claude Code-style system blocks:
//
//	system[0]: billing header (no cache_control)
//	system[1]: agent identifier (no cache_control)
//	system[2]: optional static Claude Code prompt (global ephemeral cache_control)
//	system[3]: text-output guidance plus verified client-provided dynamic sections
//	client system messages: moved to the first user message when strict mode is disabled
func checkSystemInstructionsWithFullSystemPrompt(payload []byte, strictMode bool, cchSigning bool, oauthMode bool, version, entrypoint, workload string, fullSystemPrompt bool) []byte {
	system := gjson.GetBytes(payload, "system")
	messageText := claudeFirstUserText(payload)

	billingText := generateBillingHeader(payload, cchSigning, version, messageText, entrypoint, workload)
	billingBlock := buildTextBlock(billingText, nil)

	agentBlock := claudeIdentityBlock(entrypoint, oauthMode)
	systemResult := "[" + billingBlock + "," + agentBlock
	plainSystemParts := claudePlainSystemTextParts(system)
	trustedClientEnvelope := hasLeadingClaudeCloakEnvelope(plainSystemParts) || containsExactClaudeCodeStaticPrompt(plainSystemParts)
	userSystemParts := stripLeadingClaudeCloakTextParts(plainSystemParts)
	officialClientDynamicBlock := claudeCodeOfficialDynamicSystemBlock(system)
	clientStaticPrompt := detectClaudeCodeStaticPromptVariant(userSystemParts)
	clientDynamicPrefix := detectClaudeCodeDynamicPromptPrefixVariant(userSystemParts)
	dynamicSystemPromptParts := []string(nil)
	forwardedSystemParts := userSystemParts
	if fullSystemPrompt {
		dynamicSections, forwardedParts := splitClaudeCodeSystemPromptParts(userSystemParts, trustedClientEnvelope, officialClientDynamicBlock)
		forwardedSystemParts = forwardedParts
		dynamicSystemPromptParts = claudeCodeDynamicSectionTexts(dynamicSections)
		staticCacheControl := map[string]string{"type": "ephemeral"}
		if cchSigning || oauthMode {
			staticCacheControl["scope"] = helps.OfficialClaudeCodeOAuthProfile().GlobalCacheScope
		}
		if oauthMode {
			profile := helps.OfficialClaudeCodeOAuthProfile()
			staticCacheControl["ttl"] = profile.CacheTTL
		}

		model := gjson.GetBytes(payload, "model").String()
		simpleSystemPrompt := helps.ClaudeCodeSimpleSystemPromptOverride(os.Getenv("CLAUDE_CODE_SIMPLE_SYSTEM_PROMPT"))
		investigateFirst := helps.ClaudeCodeInvestigateFirstMode(os.Getenv("CLAUDE_CODE_INVESTIGATE_FIRST"))
		staticPromptText := claudeCodeStaticSystemPromptForPayloadWithOptions(payload, simpleSystemPrompt, investigateFirst)
		dynamicPromptText := helps.ClaudeCodeDynamicPromptPrefixForOptions(model, simpleSystemPrompt, investigateFirst)
		if clientStaticPrompt != "" {
			clientSimpleSystemPrompt := false
			clientInvestigateFirst := helps.ClaudeCodeInvestigateFirstOff
			switch clientStaticPrompt {
			case helps.ClaudeCodeLeanStaticSystemPrompt, helps.ClaudeCodeFableLeanStaticSystemPrompt:
				clientSimpleSystemPrompt = true
			default:
				if isClaudeCodeCompactStaticPrompt(clientStaticPrompt) {
					clientInvestigateFirst = helps.ClaudeCodeInvestigateFirstCompact
				}
			}
			staticPromptText = claudeCodeStaticSystemPromptForPayloadWithOptions(payload, &clientSimpleSystemPrompt, clientInvestigateFirst)
			dynamicPromptText = helps.ClaudeCodeDynamicPromptPrefixForOptions(model, &clientSimpleSystemPrompt, clientInvestigateFirst)
		}
		if clientDynamicPrefix != "" {
			dynamicPromptText = clientDynamicPrefix
		}
		systemResult += "," + buildTextBlock(staticPromptText, staticCacheControl)

		if len(dynamicSystemPromptParts) > 0 {
			dynamicPromptText += "\n\n" + strings.Join(dynamicSystemPromptParts, "\n\n")
		}
		dynamicCacheControl := map[string]string{"type": "ephemeral"}
		if oauthMode {
			dynamicCacheControl["ttl"] = helps.OfficialClaudeCodeOAuthProfile().CacheTTL
		}
		systemResult += "," + buildTextBlock(dynamicPromptText, dynamicCacheControl)
	}
	systemResult += "]"
	payload, _ = sjson.SetRawBytes(payload, "system", []byte(systemResult))

	// Collect user system instructions and prepend to first user message
	if !strictMode {
		if len(forwardedSystemParts) > 0 {
			combined := strings.Join(forwardedSystemParts, "\n\n")
			if oauthMode {
				combined = sanitizeForwardedSystemPrompt(combined)
			}
			if strings.TrimSpace(combined) != "" {
				payload = prependToFirstUserMessage(payload, combined)
			}
		}
	}

	return payload
}

func claudeCodeStaticSystemPromptForPayload(payload []byte) string {
	return claudeCodeStaticSystemPromptForPayloadWithOptions(payload, nil, helps.ClaudeCodeInvestigateFirstOff)
}

func claudeCodeStaticSystemPromptForPayloadWithOptions(payload []byte, simpleSystemPrompt *bool, investigateFirst string) string {
	hasBash := false
	hasTaskCreate := false
	hasTodoWrite := false
	tools := gjson.GetBytes(payload, "tools")
	if tools.IsArray() {
		tools.ForEach(func(_, tool gjson.Result) bool {
			name := tool.Get("name").String()
			if mapped, ok := oauthToolRenameMap[name]; ok {
				name = mapped
			}
			switch name {
			case "Bash":
				hasBash = true
			case "TaskCreate":
				hasTaskCreate = true
			case "DeferredToolPlaceholder":
				// The default native registry includes deferred TaskCreate even
				// though it is absent from the eager wire tools list.
				hasTaskCreate = true
			case "TodoWrite":
				hasTodoWrite = true
			}
			return true
		})
	}
	model := gjson.GetBytes(payload, "model").String()
	return helps.ClaudeCodeStaticSystemPromptForOptions(model, hasBash, hasTaskCreate, hasTodoWrite, simpleSystemPrompt, investigateFirst)
}

var claudeBillingSystemBlockPattern = regexp.MustCompile(`^x-anthropic-billing-header: cc_version=[0-9]+\.[0-9]+\.[0-9]+\.[0-9a-fA-F]{3}; cc_entrypoint=[a-z0-9-]{1,32};(?: cch=[0-9a-fA-F]{5};)?(?: cc_workload=[A-Za-z0-9_-]{1,128};)?(?: cc_is_subagent=true;)?(?: cc_prev_req=[A-Za-z0-9_-]{1,128};)?$`)

func isKnownClaudeCloakIdentity(text string) bool {
	switch strings.TrimSpace(text) {
	case "You are a Claude agent, built on Anthropic's Claude Agent SDK.",
		"You are Claude Code, Anthropic's official CLI for Claude.",
		"You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.":
		return true
	default:
		return false
	}
}

func hasLeadingClaudeCloakEnvelope(parts []string) bool {
	return len(parts) >= 2 &&
		claudeBillingSystemBlockPattern.MatchString(strings.TrimSpace(parts[0])) &&
		isKnownClaudeCloakIdentity(parts[1])
}

func stripLeadingClaudeCloakTextParts(parts []string) []string {
	if hasLeadingClaudeCloakEnvelope(parts) {
		return parts[2:]
	}
	return parts
}

func claudePlainSystemTextParts(system gjson.Result) []string {
	var parts []string
	if system.IsArray() {
		system.ForEach(func(_, part gjson.Result) bool {
			if part.Get("type").String() == "text" {
				txt := part.Get("text").String()
				if strings.TrimSpace(txt) != "" {
					parts = append(parts, txt)
				}
			}
			return true
		})
	} else if system.Type == gjson.String && strings.TrimSpace(system.String()) != "" {
		parts = append(parts, system.String())
	}
	return parts
}

func splitClaudeCodeSystemPromptParts(parts []string, trustedClientEnvelope bool, officialClientDynamicBlock string) (dynamicSystemPromptParts []claudeCodeDynamicSection, forwardedSystemParts []string) {
	var dynamicSections []claudeCodeDynamicSection
	seenDynamicSections := make(map[string]struct{})
	for _, part := range parts {
		if officialClientDynamicBlock != "" && part == officialClientDynamicBlock {
			if dynamicRemainder, ok := stripClaudeCodeDynamicPromptPrefix(part); ok {
				dynamicRemainder = strings.TrimSpace(dynamicRemainder)
				if dynamicRemainder != "" {
					key := "official-block\x00" + strings.TrimSpace(normalizeClaudePromptLineEndings(dynamicRemainder))
					if _, exists := seenDynamicSections[key]; !exists {
						seenDynamicSections[key] = struct{}{}
						dynamicSections = append(dynamicSections, claudeCodeDynamicSection{text: dynamicRemainder})
					}
				}
				continue
			}
		}
		cleaned, staticPromptRemoved := removeClaudeCodeStaticPromptDuplicates(part)
		partDynamicSections, remaining := partitionClaudeCodeDynamicPromptSections(cleaned, trustedClientEnvelope || staticPromptRemoved)
		for _, section := range partDynamicSections {
			key := section.heading + "\x00" + strings.TrimSpace(normalizeClaudePromptLineEndings(section.text))
			if _, exists := seenDynamicSections[key]; exists {
				continue
			}
			seenDynamicSections[key] = struct{}{}
			dynamicSections = append(dynamicSections, section)
		}
		if strings.TrimSpace(remaining) != "" {
			forwardedSystemParts = append(forwardedSystemParts, remaining)
		}
	}
	return dynamicSections, forwardedSystemParts
}

func claudeCodeOfficialDynamicSystemBlock(system gjson.Result) string {
	if !system.IsArray() {
		return ""
	}
	blocks := system.Array()
	if len(blocks) < 4 || blocks[0].Get("type").String() != "text" || blocks[1].Get("type").String() != "text" ||
		blocks[2].Get("type").String() != "text" || blocks[3].Get("type").String() != "text" {
		return ""
	}
	if !claudeBillingSystemBlockPattern.MatchString(strings.TrimSpace(blocks[0].Get("text").String())) ||
		!isKnownClaudeCloakIdentity(blocks[1].Get("text").String()) {
		return ""
	}
	staticText := blocks[2].Get("text").String()
	staticMatch := false
	for _, prompt := range claudeCodeStaticPromptVariants() {
		if staticText == prompt {
			staticMatch = true
			break
		}
	}
	if !staticMatch {
		return ""
	}
	dynamicText := blocks[3].Get("text").String()
	if _, ok := stripClaudeCodeDynamicPromptPrefix(dynamicText); !ok {
		return ""
	}
	return dynamicText
}

func stripClaudeCodeDynamicPromptPrefix(text string) (string, bool) {
	for _, prompt := range claudeCodeDynamicPromptPrefixVariants() {
		if text == prompt {
			return "", true
		}
		if strings.HasPrefix(text, prompt) && claudePromptSectionHasIndependentBoundaries(text, 0, len(prompt)) {
			return strings.TrimSpace(text[len(prompt):]), true
		}
	}
	return text, false
}

func removeClaudeCodeStaticPromptDuplicates(text string) (string, bool) {
	cleaned := strings.TrimSpace(normalizeClaudePromptLineEndings(text))
	trustedDynamicBoundary := false
	for _, prompt := range claudeCodeStaticPromptVariants() {
		staticPrompt := strings.TrimSpace(normalizeClaudePromptLineEndings(prompt))
		if cleaned == staticPrompt {
			return "", true
		}
		if strings.HasPrefix(cleaned, staticPrompt) &&
			claudePromptSectionHasIndependentBoundaries(cleaned, 0, len(staticPrompt)) {
			cleaned = strings.TrimSpace(cleaned[len(staticPrompt):])
			trustedDynamicBoundary = true
			break
		}
	}

	for _, dynamicPrefix := range claudeCodeDynamicPromptPrefixVariants() {
		prefix := strings.TrimSpace(normalizeClaudePromptLineEndings(dynamicPrefix))
		if cleaned == prefix {
			return "", true
		}
		if strings.HasPrefix(cleaned, prefix) &&
			claudePromptSectionHasIndependentBoundaries(cleaned, 0, len(prefix)) {
			remainder := strings.TrimSpace(cleaned[len(prefix):])
			if heading := claudeCodeDynamicPromptHeading(firstClaudePromptLine(remainder)); heading != "" {
				cleaned = remainder
				trustedDynamicBoundary = true
				break
			}
		}
	}

	// Clients may split or interleave Claude Code's prompt blocks with their own
	// instructions. Remove only byte-for-byte official sections at independent,
	// top-level boundaries; quoted, fenced, or inline customer text survives.
	removedExactSection := false
	officialSections := []string{
		helps.ClaudeCodeIntro,
		helps.ClaudeCodeSystem,
		helps.ClaudeCodeMidConvSystem,
		helps.ClaudeCodeDoingTasks,
		helps.ClaudeCodeExecutingActionsWithCare,
		helps.ClaudeCodeCompactExecutingActionsWithCare,
		helps.ClaudeCodeUsingTools,
		helps.ClaudeCodeUsingToolsWithoutBash,
		helps.ClaudeCodeUsingToolsBashWithoutTask,
		helps.ClaudeCodeUsingToolsWithoutBashTaskCreate,
		helps.ClaudeCodeUsingToolsWithoutBashTodoWrite,
		helps.ClaudeCodeUsingToolsBashTodoWrite,
		helps.ClaudeCodeToneAndStyle,
		helps.ClaudeCodeTextOutput,
	}
	officialSections = append(officialSections, claudeCodeStaticPromptVariants()...)
	officialSections = append(officialSections, claudeCodeDynamicPromptPrefixVariants()...)
	for _, officialSection := range officialSections {
		section := strings.TrimSpace(normalizeClaudePromptLineEndings(officialSection))
		withoutSection, removedSection := removeStandaloneClaudePromptSection(cleaned, section)
		if removedSection {
			removedExactSection = true
			cleaned = withoutSection
		}
	}

	if !trustedDynamicBoundary && !removedExactSection {
		return text, false
	}
	return strings.TrimSpace(cleaned), trustedDynamicBoundary
}

func removeStandaloneClaudePromptSection(text, section string) (string, bool) {
	if text == "" || section == "" {
		return text, false
	}
	searchStart := 0
	copyStart := 0
	removed := false
	var result strings.Builder
	for searchStart < len(text) {
		relativeStart := strings.Index(text[searchStart:], section)
		if relativeStart < 0 {
			break
		}
		start := searchStart + relativeStart
		end := start + len(section)
		if claudePromptSectionHasIndependentBoundaries(text, start, end) {
			if !removed {
				result.Grow(len(text))
			}
			result.WriteString(text[copyStart:start])
			copyStart = end
			searchStart = end
			removed = true
			continue
		}
		searchStart = start + 1
	}
	if !removed {
		return text, false
	}
	result.WriteString(text[copyStart:])
	return result.String(), true
}

func claudePromptSectionHasIndependentBoundaries(text string, start, end int) bool {
	if start < 0 || end < start || end > len(text) || claudePromptOffsetInsideFence(text, start) {
		return false
	}
	if start > 0 {
		if text[start-1] != '\n' {
			return false
		}
		previousLineEnd := start - 1
		previousLineStart := strings.LastIndexByte(text[:previousLineEnd], '\n') + 1
		if strings.Trim(text[previousLineStart:previousLineEnd], " \t\r") != "" {
			return false
		}
	}
	if end < len(text) {
		if text[end] != '\n' {
			return false
		}
		nextLineStart := end + 1
		nextLineEnd := len(text)
		if relativeEnd := strings.IndexByte(text[nextLineStart:], '\n'); relativeEnd >= 0 {
			nextLineEnd = nextLineStart + relativeEnd
		}
		if strings.Trim(text[nextLineStart:nextLineEnd], " \t\r") != "" {
			return false
		}
	}
	return true
}

func claudePromptOffsetInsideFence(text string, offset int) bool {
	if offset <= 0 || offset > len(text) {
		return false
	}
	inFence := false
	var fenceMarker byte
	fenceLength := 0
	literalFence := ""
	lineStart := 0
	for lineStart < offset {
		lineEnd := len(text)
		if relativeEnd := strings.IndexByte(text[lineStart:], '\n'); relativeEnd >= 0 {
			lineEnd = lineStart + relativeEnd
		}
		line := text[lineStart:lineEnd]
		trimmed := strings.TrimSpace(line)
		if trimmed == `"""` || trimmed == `'''` {
			if !inFence {
				inFence = true
				fenceMarker = 0
				fenceLength = 3
				literalFence = trimmed
			} else if fenceMarker == 0 && literalFence == trimmed {
				inFence = false
				fenceLength = 0
				literalFence = ""
			}
		} else if marker, length, remainder, okFence := claudePromptMarkdownFence(line); okFence {
			if !inFence {
				inFence = true
				fenceMarker = marker
				fenceLength = length
				literalFence = ""
			} else if fenceMarker == marker && length >= fenceLength && strings.TrimSpace(remainder) == "" {
				inFence = false
				fenceMarker = 0
				fenceLength = 0
			}
		}
		if lineEnd == len(text) {
			break
		}
		lineStart = lineEnd + 1
	}
	return inFence
}

func claudePromptMarkdownFence(line string) (marker byte, length int, remainder string, ok bool) {
	indent := 0
	for indent < len(line) && line[indent] == ' ' && indent < 4 {
		indent++
	}
	if indent > 3 || indent >= len(line) || (line[indent] != '`' && line[indent] != '~') {
		return 0, 0, "", false
	}
	marker = line[indent]
	end := indent
	for end < len(line) && line[end] == marker {
		end++
	}
	if end-indent < 3 {
		return 0, 0, "", false
	}
	return marker, end - indent, line[end:], true
}

var claudeCodeToolPromptConfigurations = [][3]bool{
	{true, true, false},
	{true, false, true},
	{true, false, false},
	{false, true, false},
	{false, false, true},
	{false, false, false},
}

var claudeCodeStaticPromptVariantCache = buildClaudeCodeStaticPromptVariants()

func buildClaudeCodeStaticPromptVariants() []string {
	variants := []string{
		helps.ClaudeCodeLeanStaticSystemPrompt,
		helps.ClaudeCodeFableLeanStaticSystemPrompt,
	}
	for _, tools := range claudeCodeToolPromptConfigurations {
		variants = append(variants,
			helps.ClaudeCodeStaticSystemPromptForTools(tools[0], tools[1], tools[2]),
			helps.ClaudeCodeCompactStaticSystemPromptForTools(tools[0], tools[1], tools[2]),
			helps.ClaudeCodeMidConvStaticSystemPromptForTools(tools[0], tools[1], tools[2]),
		)
	}
	return variants
}

func claudeCodeStaticPromptVariants() []string {
	return claudeCodeStaticPromptVariantCache
}

var claudeCodeDynamicPromptPrefixVariantCache = []string{
	helps.ClaudeCodeFableDynamicPromptPrefix,
	helps.ClaudeCodeMythosDynamicPromptPrefix,
	helps.ClaudeCodeFableNormalDynamicPromptPrefix,
	helps.ClaudeCodeMythosNormalDynamicPromptPrefix,
	helps.ClaudeCodeInvestigateFirstDynamicPromptPrefix,
	helps.ClaudeCodeOpus48DynamicPromptPrefix + "\n\n" + helps.ClaudeCodeInvestigateFirst,
	helps.ClaudeCodeTextOutput,
	helps.ClaudeCodeOpus48DynamicPromptPrefix,
}

func claudeCodeDynamicPromptPrefixVariants() []string {
	return claudeCodeDynamicPromptPrefixVariantCache
}

func detectClaudeCodeStaticPromptVariant(parts []string) string {
	return detectStandaloneClaudeCodePromptVariant(parts, claudeCodeStaticPromptVariants())
}

func detectClaudeCodeDynamicPromptPrefixVariant(parts []string) string {
	return detectStandaloneClaudeCodePromptVariant(parts, claudeCodeDynamicPromptPrefixVariants())
}

func detectStandaloneClaudeCodePromptVariant(parts, variants []string) string {
	for _, part := range parts {
		normalized := strings.TrimSpace(normalizeClaudePromptLineEndings(part))
		for _, variant := range variants {
			prompt := strings.TrimSpace(normalizeClaudePromptLineEndings(variant))
			searchStart := 0
			for searchStart <= len(normalized)-len(prompt) {
				relativeStart := strings.Index(normalized[searchStart:], prompt)
				if relativeStart < 0 {
					break
				}
				start := searchStart + relativeStart
				end := start + len(prompt)
				if claudePromptSectionHasIndependentBoundaries(normalized, start, end) {
					return variant
				}
				searchStart = start + 1
			}
		}
	}
	return ""
}

func isClaudeCodeCompactStaticPrompt(prompt string) bool {
	for _, tools := range claudeCodeToolPromptConfigurations {
		if prompt == helps.ClaudeCodeCompactStaticSystemPromptForTools(tools[0], tools[1], tools[2]) {
			return true
		}
	}
	return false
}

func containsExactClaudeCodeStaticPrompt(parts []string) bool {
	for _, part := range parts {
		normalized := strings.TrimSpace(normalizeClaudePromptLineEndings(part))
		for _, prompt := range claudeCodeStaticPromptVariants() {
			staticPrompt := strings.TrimSpace(normalizeClaudePromptLineEndings(prompt))
			if normalized == staticPrompt {
				return true
			}
			if _, found := removeStandaloneClaudePromptSection(normalized, staticPrompt); found {
				return true
			}
		}
	}
	return false
}

func firstClaudePromptLine(text string) string {
	if newline := strings.IndexByte(text, '\n'); newline >= 0 {
		return text[:newline]
	}
	return text
}

type claudeCodeDynamicSection struct {
	heading string
	text    string
}

func partitionClaudeCodeDynamicPromptSections(text string, trustOfficialBoundary bool) ([]claudeCodeDynamicSection, string) {
	ranges := claudeCodeDynamicSectionRanges(text)
	if len(ranges) == 0 {
		return nil, text
	}

	sections := make([]claudeCodeDynamicSection, 0, len(ranges))
	var remaining strings.Builder
	cursor := 0
	for _, sectionRange := range ranges {
		end := sectionRange.end
		sectionText := strings.TrimSpace(text[sectionRange.start:end])
		section := claudeCodeDynamicSection{heading: sectionRange.heading, text: sectionText}
		promote := sectionText != "" && trustOfficialBoundary
		if promote {
			if sectionRange.start > cursor {
				remaining.WriteString(text[cursor:sectionRange.start])
			}
			sections = append(sections, section)
			cursor = end
		}
	}
	if cursor < len(text) {
		remaining.WriteString(text[cursor:])
	}
	return sections, strings.TrimSpace(remaining.String())
}

type claudeCodeDynamicSectionRange struct {
	heading string
	start   int
	end     int
}

func claudeCodeDynamicSectionRanges(text string) []claudeCodeDynamicSectionRange {
	type topLevelHeading struct {
		heading string
		start   int
	}
	var headings []topLevelHeading
	inFence := false
	var fenceMarker byte
	fenceLength := 0
	literalFence := ""
	offset := 0
	for offset < len(text) {
		lineStart := offset
		nextLine := strings.IndexByte(text[offset:], '\n')
		lineEnd := len(text)
		if nextLine >= 0 {
			lineEnd = offset + nextLine
			offset = lineEnd + 1
		} else {
			offset = len(text)
		}
		line := text[lineStart:lineEnd]
		trimmed := strings.TrimSpace(line)
		if trimmed == `"""` || trimmed == `'''` {
			if !inFence {
				inFence = true
				fenceMarker = 0
				fenceLength = 3
				literalFence = trimmed
			} else if fenceMarker == 0 && literalFence == trimmed {
				inFence = false
				fenceLength = 0
				literalFence = ""
			}
			continue
		}
		if marker, length, remainder, okFence := claudePromptMarkdownFence(line); okFence {
			if !inFence {
				inFence = true
				fenceMarker = marker
				fenceLength = length
				literalFence = ""
			} else if fenceMarker == marker && length >= fenceLength && strings.TrimSpace(remainder) == "" {
				inFence = false
				fenceMarker = 0
				fenceLength = 0
			}
			continue
		}
		if inFence {
			continue
		}
		if isClaudeTopLevelPromptHeading(line) {
			headings = append(headings, topLevelHeading{
				heading: claudeCodeDynamicPromptHeading(line),
				start:   lineStart,
			})
		}
	}
	ranges := make([]claudeCodeDynamicSectionRange, 0, len(headings))
	for i, heading := range headings {
		if heading.heading == "" {
			continue
		}
		end := len(text)
		if i+1 < len(headings) {
			end = headings[i+1].start
		}
		ranges = append(ranges, claudeCodeDynamicSectionRange{
			heading: heading.heading,
			start:   heading.start,
			end:     end,
		})
	}
	return ranges
}

func isClaudeTopLevelPromptHeading(line string) bool {
	return strings.HasPrefix(line, "# ")
}

func claudeCodeDynamicPromptHeading(line string) string {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "# Output Style: ") && strings.TrimSpace(strings.TrimPrefix(trimmed, "# Output Style: ")) != "" {
		return trimmed
	}
	for _, heading := range claudeCodeDynamicPromptHeadingOrder() {
		if trimmed == heading {
			return heading
		}
	}
	return ""
}

func claudeCodeDynamicSectionTexts(sections []claudeCodeDynamicSection) []string {
	if len(sections) == 0 {
		return nil
	}
	texts := make([]string, 0, len(sections))
	for _, section := range sections {
		if strings.TrimSpace(section.text) != "" {
			texts = append(texts, section.text)
		}
	}
	return texts
}

func claudeCodeDynamicPromptHeadingOrder() []string {
	return []string{
		"# Session-specific guidance",
		"# auto memory",
		"# Memory",
		"# Environment",
		"# Language",
		"# Background Session",
		"# Scratchpad Directory",
		"# Context management",
		"# Focus mode",
	}
}

func normalizeClaudePromptLineEndings(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	return strings.ReplaceAll(text, "\r", "\n")
}

func claudeIdentityBlock(entrypoint string, _ bool) string {
	if strings.EqualFold(strings.TrimSpace(entrypoint), "sdk-cli") {
		return buildTextBlock("You are a Claude agent, built on Anthropic's Claude Agent SDK.", nil)
	}
	return buildTextBlock("You are Claude Code, Anthropic's official CLI for Claude.", nil)
}

// sanitizeForwardedSystemPrompt keeps the client-provided system context intact
// when it is moved into the first user message for Claude OAuth cloaking.
func sanitizeForwardedSystemPrompt(text string) string {
	return text
}

// buildTextBlock constructs a JSON text block using JavaScript-compatible
// string escaping. Go's default HTML escaping would rewrite Claude prompt tags.
func buildTextBlock(text string, cacheControl map[string]string) string {
	var block bytes.Buffer
	block.WriteString(`{"type":"text","text":`)
	block.Write(marshalClaudeJSONString(text))
	if cacheControl != nil && len(cacheControl) > 0 {
		block.WriteString(`,"cache_control":`)
		block.Write(buildCacheControlJSON(cacheControl))
	}
	block.WriteByte('}')
	return block.String()
}

func marshalClaudeJSONString(value string) []byte {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if errEncode := encoder.Encode(value); errEncode != nil {
		return []byte(`""`)
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'})
}

func buildCacheControlJSON(cacheControl map[string]string) []byte {
	cc := []byte(`{}`)
	cacheType := strings.TrimSpace(cacheControl["type"])
	if cacheType == "" {
		cacheType = "ephemeral"
	}
	cc, _ = sjson.SetBytes(cc, "type", cacheType)
	if ttl := strings.TrimSpace(cacheControl["ttl"]); ttl != "" {
		cc, _ = sjson.SetBytes(cc, "ttl", ttl)
	}
	if scope := strings.TrimSpace(cacheControl["scope"]); scope != "" {
		cc, _ = sjson.SetBytes(cc, "scope", scope)
	}
	return cc
}

// prependToFirstUserMessage prepends text content to the first user message.
// This avoids putting non-Claude-Code system instructions in system[] which
// triggers Anthropic's extra usage billing for OAuth-proxied requests.
func prependToFirstUserMessage(payload []byte, text string) []byte {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return payload
	}

	// Find the first user message index
	firstUserIdx := -1
	messages.ForEach(func(idx, msg gjson.Result) bool {
		if msg.Get("role").String() == "user" {
			firstUserIdx = int(idx.Int())
			return false
		}
		return true
	})

	if firstUserIdx < 0 {
		return payload
	}

	prefixBlock := fmt.Sprintf(`<system-reminder>
As you answer the user's questions, you can use the following context from the system:
%s

IMPORTANT: this context may or may not be relevant to your tasks. You should not respond to this context unless it is highly relevant to your task.
</system-reminder>
`, text)

	contentPath := fmt.Sprintf("messages.%d.content", firstUserIdx)
	content := gjson.GetBytes(payload, contentPath)

	if content.IsArray() {
		items := []string{buildTextBlock(prefixBlock, nil)}
		content.ForEach(func(_, item gjson.Result) bool {
			items = append(items, item.Raw)
			return true
		})
		if updated, errSet := sjson.SetRawBytes(payload, contentPath, rawJSONArray(items)); errSet == nil {
			payload = updated
		}
	} else if content.Type == gjson.String {
		items := []string{
			buildTextBlock(prefixBlock, nil),
			buildTextBlock(content.String(), nil),
		}
		if updated, errSet := sjson.SetRawBytes(payload, contentPath, rawJSONArray(items)); errSet == nil {
			payload = updated
		}
	}

	return payload
}

func resolvedClaudeCloakMode(cfg *config.Config, cloakCfg *config.CloakConfig, authMode string) string {
	mode := "auto"
	if cfg != nil && cfg.DisableClaudeCloakMode {
		mode = "never"
	}
	if strings.TrimSpace(authMode) != "" {
		mode = authMode
	}
	if cloakCfg != nil && strings.TrimSpace(cloakCfg.Mode) != "" {
		mode = cloakCfg.Mode
	}
	return mode
}

func shouldApplyClaudeCloaking(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth) bool {
	cloakCfg := resolveClaudeKeyCloakConfig(cfg, auth)
	authMode, _, _, _, _ := getCloakConfigFromAuth(auth)
	return helps.ShouldCloak(resolvedClaudeCloakMode(cfg, cloakCfg, authMode), getClientUserAgent(ctx))
}

// applyCloaking applies cloaking transformations to the payload based on config and client.
// Cloaking includes: system prompt injection, fake user ID, and sensitive word obfuscation.
func applyCloaking(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, payload []byte, model string, apiKey string) ([]byte, error) {
	clientUserAgent := getClientUserAgent(ctx)
	// Official first-party OAuth cloak payloads carry a placeholder that is
	// signed after every request transformation. Real Claude Code requests pass
	// through untouched when auto cloaking is selected.
	firstPartyOAuth := isClaudeOAuthAuth(auth, apiKey)
	_, baseURL := claudeCreds(auth)
	firstPartyOAuth = firstPartyOAuth && isClaudeFirstPartyBaseURL(baseURL)
	useCCHSigning := claudeCCHSigningEnabled(cfg, firstPartyOAuth, baseURL)

	// Get cloak config from ClaudeKey configuration
	cloakCfg := resolveClaudeKeyCloakConfig(cfg, auth)
	attrMode, attrStrict, attrWords, attrCache, attrFullSystemPrompt := getCloakConfigFromAuth(auth)

	// Determine cloak settings. Precedence (low -> high):
	//   built-in "auto" default
	//   -> global disable-claude-cloak-mode switch (forces "never")
	//   -> per-credential settings from auth attributes/metadata
	//   -> per claude-api-key cloak config
	cloakMode := resolvedClaudeCloakMode(cfg, cloakCfg, attrMode)
	strictMode := attrStrict
	sensitiveWords := attrWords
	cacheUserID := true
	fullSystemPrompt := true

	if attrCache != nil {
		cacheUserID = *attrCache
	}
	if attrFullSystemPrompt != nil {
		fullSystemPrompt = *attrFullSystemPrompt
	}

	if cloakCfg != nil {
		if cloakCfg.StrictMode {
			strictMode = true
		}
		if len(cloakCfg.SensitiveWords) > 0 {
			sensitiveWords = cloakCfg.SensitiveWords
		}
		if cloakCfg.CacheUserID != nil {
			cacheUserID = *cloakCfg.CacheUserID
		}
		if cloakCfg.FullSystemPrompt != nil {
			fullSystemPrompt = *cloakCfg.FullSystemPrompt
		}
	}

	// Determine if cloaking should be applied
	if !helps.ShouldCloak(cloakMode, clientUserAgent) {
		return payload, nil
	}

	billingVersion := helps.DefaultClaudeVersion(cfg)
	if firstPartyOAuth {
		billingVersion = helps.OfficialClaudeCodeOAuthProfile().Version
	}
	entrypoint := parseEntrypointFromUA(clientUserAgent)
	workload := getWorkloadFromContext(ctx)
	payload = checkSystemInstructionsWithFullSystemPrompt(
		payload,
		strictMode,
		useCCHSigning,
		firstPartyOAuth,
		billingVersion,
		entrypoint,
		workload,
		fullSystemPrompt,
	)

	// Inject fake user ID
	var errFakeUserID error
	accountUUID, errAccountUUID := claudeOAuthAccountUUID(auth)
	if errAccountUUID != nil {
		return nil, errAccountUUID
	}
	authDir := ""
	if cfg != nil {
		authDir = cfg.AuthDir
	}
	payload, errFakeUserID = injectFakeUserID(ctx, payload, claudeProxyInstallationIdentityScope, accountUUID, authDir, cacheUserID)
	if errFakeUserID != nil {
		return nil, errFakeUserID
	}
	cacheTTL := ""
	if firstPartyOAuth {
		cacheTTL = helps.OfficialClaudeCodeOAuthProfile().CacheTTL
	}
	payload = ensureClaudeCodeCurrentUserCacheControlWithTTL(payload, cacheTTL)
	// Claude Code's explicit OAuth breakpoints are authoritative. A root-level
	// automatic cache directive would consume a fifth slot or conflict on TTL.
	if gjson.GetBytes(payload, "cache_control").Exists() {
		if updated, errDelete := sjson.DeleteBytes(payload, "cache_control"); errDelete == nil {
			payload = updated
		}
	}

	// Apply sensitive word obfuscation
	if len(sensitiveWords) > 0 {
		matcher := helps.BuildSensitiveWordMatcher(sensitiveWords)
		payload = helps.ObfuscateSensitiveWords(payload, matcher)
	}

	return payload, nil
}

func ensureClaudeCodeCurrentUserCacheControl(payload []byte) []byte {
	return ensureClaudeCodeCurrentUserCacheControlWithTTL(payload, "")
}

func ensureClaudeCodeCurrentUserCacheControlWithTTL(payload []byte, ttl string) []byte {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return payload
	}

	lastUserIdx := -1
	messages.ForEach(func(index, msg gjson.Result) bool {
		if msg.Get("role").String() == "user" {
			lastUserIdx = int(index.Int())
		}
		return true
	})
	if lastUserIdx < 0 {
		return payload
	}
	cacheControl := map[string]string{"type": "ephemeral"}
	if ttl = strings.TrimSpace(ttl); ttl != "" {
		cacheControl["ttl"] = ttl
	}

	contentPath := fmt.Sprintf("messages.%d.content", lastUserIdx)
	content := gjson.GetBytes(payload, contentPath)
	if content.IsArray() {
		targetIdx := -1
		content.ForEach(func(index, _ gjson.Result) bool {
			targetIdx = int(index.Int())
			return true
		})
		if targetIdx < 0 {
			return payload
		}
		cacheControlPath := fmt.Sprintf("%s.%d.cache_control", contentPath, targetIdx)
		expectedCacheControl := buildCacheControlJSON(cacheControl)
		if existing := gjson.GetBytes(payload, cacheControlPath); existing.Exists() && existing.Raw == string(expectedCacheControl) {
			return payload
		}
		if updated, errSet := sjson.SetRawBytes(payload, cacheControlPath, expectedCacheControl); errSet == nil {
			return updated
		}
		return payload
	}
	if content.Type == gjson.String {
		newContent := rawJSONArray([]string{buildTextBlock(content.String(), cacheControl)})
		if updated, errSet := sjson.SetRawBytes(payload, contentPath, newContent); errSet == nil {
			return updated
		}
	}
	return payload
}

// ensureCacheControl injects cache_control breakpoints into the payload for optimal prompt caching.
// According to Anthropic's documentation, cache prefixes are created in order: tools -> system -> messages.
// This function adds cache_control to:
// 1. The LAST tool in the tools array (caches all tool definitions)
// 2. The LAST system prompt element
// 3. The SECOND-TO-LAST user turn (caches conversation history for multi-turn)
//
// Up to 4 cache breakpoints are allowed per request. Tools, System, and Messages are INDEPENDENT breakpoints.
// This enables up to 90% cost reduction on cached tokens (cache read = 0.1x base price).
// See: https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching
func ensureCacheControl(payload []byte) []byte {
	// 1. Inject cache_control into the LAST tool (caches all tool definitions)
	// Tools are cached first in the hierarchy, so this is the most important breakpoint.
	payload = injectToolsCacheControl(payload)

	// 2. Inject cache_control into the LAST system prompt element
	// System is the second level in the cache hierarchy.
	payload = injectSystemCacheControl(payload)

	// 3. Inject cache_control into messages for multi-turn conversation caching
	// This caches the conversation history up to the second-to-last user turn.
	payload = injectMessagesCacheControl(payload)

	return payload
}

type claudeCacheControlRef struct {
	path    string
	control gjson.Result
}

func collectClaudeCacheControls(payload []byte) []claudeCacheControlRef {
	refs := make([]claudeCacheControlRef, 0, 4)
	add := func(path string, owner gjson.Result) {
		if control := owner.Get("cache_control"); control.Exists() {
			refs = append(refs, claudeCacheControlRef{path: path + ".cache_control", control: control})
		}
	}
	if control := gjson.GetBytes(payload, "cache_control"); control.Exists() {
		refs = append(refs, claudeCacheControlRef{path: "cache_control", control: control})
	}
	if tools := gjson.GetBytes(payload, "tools"); tools.IsArray() {
		tools.ForEach(func(index, tool gjson.Result) bool {
			add(fmt.Sprintf("tools.%d", index.Int()), tool)
			return true
		})
	}
	if system := gjson.GetBytes(payload, "system"); system.IsArray() {
		system.ForEach(func(index, block gjson.Result) bool {
			add(fmt.Sprintf("system.%d", index.Int()), block)
			return true
		})
	}
	if messages := gjson.GetBytes(payload, "messages"); messages.IsArray() {
		messages.ForEach(func(messageIndex, message gjson.Result) bool {
			content := message.Get("content")
			if !content.IsArray() {
				return true
			}
			content.ForEach(func(contentIndex, block gjson.Result) bool {
				blockPath := fmt.Sprintf("messages.%d.content.%d", messageIndex.Int(), contentIndex.Int())
				add(blockPath, block)
				// ToolResultBlockParam.content may itself contain cacheable text,
				// image, document, or search-result blocks. Scan this schema-owned
				// level only; arbitrary tool input schemas must remain untouched.
				if block.Get("type").String() == "tool_result" {
					if nested := block.Get("content"); nested.IsArray() {
						nested.ForEach(func(nestedIndex, nestedBlock gjson.Result) bool {
							add(fmt.Sprintf("%s.content.%d", blockPath, nestedIndex.Int()), nestedBlock)
							return true
						})
					}
				}
				return true
			})
			return true
		})
	}
	return refs
}

func countCacheControls(payload []byte) int {
	return len(collectClaudeCacheControls(payload))
}

func removeTopLevelCacheControlWhenExplicit(payload []byte) []byte {
	if !gjson.GetBytes(payload, "cache_control").Exists() {
		return payload
	}
	if countCacheControls(payload) <= 1 {
		return payload
	}
	updated, errDelete := sjson.DeleteBytes(payload, "cache_control")
	if errDelete != nil {
		return payload
	}
	return updated
}

func normalizeClaudeOAuthCacheControlTTL(payload []byte) []byte {
	ttl := helps.OfficialClaudeCodeOAuthProfile().CacheTTL
	for _, ref := range collectClaudeCacheControls(payload) {
		if ref.path == "cache_control" || !ref.control.IsObject() || ref.control.Get("type").String() != "ephemeral" {
			continue
		}
		if updated, errSet := sjson.SetBytes(payload, ref.path+".ttl", ttl); errSet == nil {
			payload = updated
		}
	}
	return payload
}

// normalizeCacheControlTTL ensures cache_control TTL values don't violate the
// prompt-caching-scope-2026-01-05 ordering constraint: a 1h-TTL block must not
// appear after a 5m-TTL block anywhere in the evaluation order.
//
// Anthropic evaluates blocks in order: tools → system (index 0..N) → messages.
// Within each section, blocks are evaluated in array order. A 5m (default) block
// followed by a 1h block at ANY later position is an error — including within
// the same section (e.g. system[1]=5m then system[3]=1h).
//
// Strategy: walk all cache_control blocks in evaluation order. Once a 5m block
// is seen, strip ttl from ALL subsequent 1h blocks (downgrading them to 5m).
func normalizeCacheControlTTL(payload []byte) []byte {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return payload
	}

	original := payload
	seen5m := false
	modified := false

	processControl := func(path string, cc gjson.Result) {
		if !cc.IsObject() {
			seen5m = true
			return
		}
		ttl := cc.Get("ttl")
		if ttl.Type != gjson.String || ttl.String() != "1h" {
			seen5m = true
			return
		}
		if !seen5m {
			return
		}
		ttlPath := path + ".ttl"
		updated, errDel := sjson.DeleteBytes(payload, ttlPath)
		if errDel != nil {
			return
		}
		payload = updated
		modified = true
	}

	for _, ref := range collectClaudeCacheControls(payload) {
		processControl(ref.path, ref.control)
	}

	if !modified {
		return original
	}
	return payload
}

// enforceCacheControlLimit removes excess cache_control blocks from a payload
// so the total does not exceed the Anthropic API limit (currently 4).
//
// Anthropic evaluates cache breakpoints in order: tools → system → messages.
// Claude Code's identity/static system breakpoints and latest user breakpoint
// are preserved ahead of redundant client/tool markers. Within each category,
// the last marker covers the largest prefix and is therefore retained longest.
func validClaudeCacheControl(control gjson.Result) bool {
	if !control.IsObject() || control.Get("type").String() != "ephemeral" {
		return false
	}
	if ttl := control.Get("ttl"); ttl.Exists() && (ttl.Type != gjson.String || (ttl.String() != "5m" && ttl.String() != "1h")) {
		return false
	}
	if scope := control.Get("scope"); scope.Exists() && (scope.Type != gjson.String || scope.String() != "global") {
		return false
	}
	return true
}

func protectedClaudeCodeCacheControlPaths(payload []byte) (map[string]struct{}, bool) {
	protected := make(map[string]struct{}, 3)
	officialStatic := false
	officialDynamic := false
	if system := gjson.GetBytes(payload, "system"); system.IsArray() {
		if block := system.Get("2"); block.Get("cache_control").Exists() {
			blockText := block.Get("text").String()
			for _, prompt := range claudeCodeStaticPromptVariants() {
				if blockText == prompt {
					protected["system.2.cache_control"] = struct{}{}
					officialStatic = true
					break
				}
			}
		}
		if block := system.Get("3"); block.Get("cache_control").Exists() {
			text := block.Get("text").String()
			if hasClaudeCodeDynamicPromptPrefix(text) {
				protected["system.3.cache_control"] = struct{}{}
				officialDynamic = true
			}
		}
	}

	lastUserIndex := -1
	if messages := gjson.GetBytes(payload, "messages"); messages.IsArray() {
		messages.ForEach(func(index, message gjson.Result) bool {
			if strings.EqualFold(strings.TrimSpace(message.Get("role").String()), "user") {
				lastUserIndex = int(index.Int())
			}
			return true
		})
	}
	if lastUserIndex >= 0 {
		contentPath := fmt.Sprintf("messages.%d.content", lastUserIndex)
		if content := gjson.GetBytes(payload, contentPath); content.IsArray() {
			lastContentIndex := len(content.Array()) - 1
			if lastContentIndex >= 0 {
				path := fmt.Sprintf("%s.%d.cache_control", contentPath, lastContentIndex)
				if gjson.GetBytes(payload, path).Exists() {
					protected[path] = struct{}{}
				}
			}
		}
	}
	return protected, officialStatic && officialDynamic
}

func hasClaudeCodeDynamicPromptPrefix(text string) bool {
	for _, prompt := range claudeCodeDynamicPromptPrefixVariants() {
		if text == prompt || strings.HasPrefix(text, prompt+"\n\n") {
			return true
		}
	}
	return false
}

func enforceCacheControlLimit(payload []byte, maxBlocks int) []byte {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return payload
	}
	if maxBlocks < 0 {
		maxBlocks = 0
	}

	// Malformed markers would be rejected upstream and can also corrupt TTL
	// ordering. Official protected markers are generated as valid objects before
	// this stage; invalid customer markers are discarded without touching text.
	for _, ref := range collectClaudeCacheControls(payload) {
		if validClaudeCacheControl(ref.control) {
			continue
		}
		if updated, errDelete := sjson.DeleteBytes(payload, ref.path); errDelete == nil {
			payload = updated
		}
	}

	protected, _ := protectedClaudeCodeCacheControlPaths(payload)

	total := countCacheControls(payload)
	if total <= maxBlocks {
		return payload
	}

	excess := total - maxBlocks

	// Automatic top-level caching overlaps explicit Claude Code breakpoints and
	// counts toward the same four-slot limit. Prefer the explicit official
	// breakpoints when both forms are present.
	if excess > 0 && gjson.GetBytes(payload, "cache_control").Exists() {
		if updated, errDel := sjson.DeleteBytes(payload, "cache_control"); errDel == nil {
			payload = updated
			excess--
		}
	}
	if excess <= 0 {
		return payload
	}

	var toolPaths, systemPaths, messagePaths []string
	for _, ref := range collectClaudeCacheControls(payload) {
		switch {
		case strings.HasPrefix(ref.path, "tools."):
			toolPaths = append(toolPaths, ref.path)
		case strings.HasPrefix(ref.path, "system."):
			systemPaths = append(systemPaths, ref.path)
		case strings.HasPrefix(ref.path, "messages."):
			messagePaths = append(messagePaths, ref.path)
		}
	}

	splitLast := func(paths []string) (early []string, last []string) {
		if len(paths) == 0 {
			return nil, nil
		}
		return paths[:len(paths)-1], paths[len(paths)-1:]
	}
	toolEarly, toolLast := splitLast(toolPaths)
	messageEarly, messageLast := splitLast(messagePaths)
	systemEarly, systemLast := splitLast(systemPaths)
	removalGroups := [][]string{
		toolEarly,
		messageEarly,
		toolLast,
		systemEarly,
		messageLast,
		systemLast,
	}
	for _, paths := range removalGroups {
		for _, path := range paths {
			if excess <= 0 {
				return payload
			}
			if _, keep := protected[path]; keep {
				continue
			}
			updated, errDel := sjson.DeleteBytes(payload, path)
			if errDel != nil {
				continue
			}
			payload = updated
			excess--
		}
	}

	// This fallback is only reachable with a caller-supplied limit below the
	// number of protected official markers. Keep the API invariant deterministic.
	for _, ref := range collectClaudeCacheControls(payload) {
		if excess <= 0 {
			break
		}
		if _, keep := protected[ref.path]; !keep {
			continue
		}
		if updated, errDelete := sjson.DeleteBytes(payload, ref.path); errDelete == nil {
			payload = updated
			excess--
		}
	}

	return payload
}

// injectMessagesCacheControl adds cache_control to the second-to-last user turn for multi-turn caching.
// Per Anthropic docs: "Place cache_control on the second-to-last User message to let the model reuse the earlier cache."
// This enables caching of conversation history, which is especially beneficial for long multi-turn conversations.
// Only adds cache_control if:
// - There are at least 2 user turns in the conversation
// - No message content already has cache_control
func injectMessagesCacheControl(payload []byte) []byte {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return payload
	}

	// Check if ANY message content already has cache_control
	hasCacheControlInMessages := false
	messages.ForEach(func(_, msg gjson.Result) bool {
		content := msg.Get("content")
		if content.IsArray() {
			content.ForEach(func(_, item gjson.Result) bool {
				if item.Get("cache_control").Exists() {
					hasCacheControlInMessages = true
					return false
				}
				return true
			})
		}
		return !hasCacheControlInMessages
	})
	if hasCacheControlInMessages {
		return payload
	}

	// Find all user message indices
	var userMsgIndices []int
	messages.ForEach(func(index gjson.Result, msg gjson.Result) bool {
		if msg.Get("role").String() == "user" {
			userMsgIndices = append(userMsgIndices, int(index.Int()))
		}
		return true
	})

	// Need at least 2 user turns to cache the second-to-last
	if len(userMsgIndices) < 2 {
		return payload
	}

	// Get the second-to-last user message index
	secondToLastUserIdx := userMsgIndices[len(userMsgIndices)-2]

	// Get the content of this message
	contentPath := fmt.Sprintf("messages.%d.content", secondToLastUserIdx)
	content := gjson.GetBytes(payload, contentPath)

	if content.IsArray() {
		// Add cache_control to the last content block of this message
		contentCount := int(content.Get("#").Int())
		if contentCount > 0 {
			cacheControlPath := fmt.Sprintf("messages.%d.content.%d.cache_control", secondToLastUserIdx, contentCount-1)
			result, err := sjson.SetBytes(payload, cacheControlPath, map[string]string{"type": "ephemeral"})
			if err != nil {
				log.Warnf("failed to inject cache_control into messages: %v", err)
				return payload
			}
			payload = result
		}
	} else if content.Type == gjson.String {
		// Convert string content to array with cache_control
		text := content.String()
		newContent := []map[string]interface{}{
			{
				"type": "text",
				"text": text,
				"cache_control": map[string]string{
					"type": "ephemeral",
				},
			},
		}
		result, err := sjson.SetBytes(payload, contentPath, newContent)
		if err != nil {
			log.Warnf("failed to inject cache_control into message string content: %v", err)
			return payload
		}
		payload = result
	}

	return payload
}

// injectToolsCacheControl adds cache_control to the last tool in the tools array.
// Per Anthropic docs: "The cache_control parameter on the last tool definition caches all tool definitions."
// This only adds cache_control if NO tool in the array already has it.
func injectToolsCacheControl(payload []byte) []byte {
	tools := gjson.GetBytes(payload, "tools")
	if !tools.Exists() || !tools.IsArray() {
		return payload
	}

	toolCount := int(tools.Get("#").Int())
	if toolCount == 0 {
		return payload
	}

	// Check if ANY tool already has cache_control - if so, don't modify tools
	hasCacheControlInTools := false
	tools.ForEach(func(_, tool gjson.Result) bool {
		if tool.Get("cache_control").Exists() {
			hasCacheControlInTools = true
			return false
		}
		return true
	})
	if hasCacheControlInTools {
		return payload
	}

	// Add cache_control to the last tool
	lastToolPath := fmt.Sprintf("tools.%d.cache_control", toolCount-1)
	result, err := sjson.SetBytes(payload, lastToolPath, map[string]string{"type": "ephemeral"})
	if err != nil {
		log.Warnf("failed to inject cache_control into tools array: %v", err)
		return payload
	}

	return result
}

// injectSystemCacheControl adds cache_control to the last element in the system prompt.
// Converts string system prompts to array format if needed.
// This only adds cache_control if NO system element already has it.
func injectSystemCacheControl(payload []byte) []byte {
	system := gjson.GetBytes(payload, "system")
	if !system.Exists() {
		return payload
	}

	if system.IsArray() {
		count := int(system.Get("#").Int())
		if count == 0 {
			return payload
		}

		// Check if ANY system element already has cache_control
		hasCacheControlInSystem := false
		system.ForEach(func(_, item gjson.Result) bool {
			if item.Get("cache_control").Exists() {
				hasCacheControlInSystem = true
				return false
			}
			return true
		})
		if hasCacheControlInSystem {
			return payload
		}

		// Add cache_control to the last system element
		lastSystemPath := fmt.Sprintf("system.%d.cache_control", count-1)
		result, err := sjson.SetBytes(payload, lastSystemPath, map[string]string{"type": "ephemeral"})
		if err != nil {
			log.Warnf("failed to inject cache_control into system array: %v", err)
			return payload
		}
		payload = result
	} else if system.Type == gjson.String {
		// Convert string system prompt to array with cache_control
		// "system": "text" -> "system": [{"type": "text", "text": "text", "cache_control": {"type": "ephemeral"}}]
		text := system.String()
		newSystem := []map[string]interface{}{
			{
				"type": "text",
				"text": text,
				"cache_control": map[string]string{
					"type": "ephemeral",
				},
			},
		}
		result, err := sjson.SetBytes(payload, "system", newSystem)
		if err != nil {
			log.Warnf("failed to inject cache_control into system string: %v", err)
			return payload
		}
		payload = result
	}

	return payload
}

func ensureModelMaxTokens(body []byte, modelID string) []byte {
	if len(body) == 0 || !gjson.ValidBytes(body) {
		return body
	}

	if maxTokens := gjson.GetBytes(body, "max_tokens"); maxTokens.Exists() {
		return body
	}

	for _, provider := range registry.GetGlobalRegistry().GetModelProviders(strings.TrimSpace(modelID)) {
		if strings.EqualFold(provider, "claude") {
			maxTokens := defaultModelMaxTokens
			if info := registry.GetGlobalRegistry().GetModelInfo(strings.TrimSpace(modelID), "claude"); info != nil && info.MaxCompletionTokens > 0 {
				maxTokens = info.MaxCompletionTokens
			}
			body, _ = sjson.SetBytes(body, "max_tokens", maxTokens)
			return body
		}
	}

	return body
}

func claudeCodeDefaultMaxTokens(modelID string) int {
	return registry.ClaudeCodeDefaultMaxTokens(modelID)
}

// claudeCodeMaxTokensUpperLimit mirrors Claude Code 2.1.216's baked model
// catalog. Unknown/custom first-party models use the native 128K fallback.
func claudeCodeMaxTokensUpperLimit(modelID string) int {
	model := strings.ToLower(strings.TrimSpace(modelID))
	switch {
	case strings.Contains(model, "claude-3-5-haiku"):
		return 8192
	case strings.Contains(model, "claude-3-haiku"):
		return 4096
	case strings.Contains(model, "claude-haiku-4-5"):
		return 64000
	case strings.Contains(model, "claude-3-5-sonnet"):
		return 8192
	case strings.Contains(model, "claude-3-7-sonnet"):
		return 64000
	case strings.Contains(model, "claude-3-sonnet"):
		return 8192
	case strings.Contains(model, "claude-3-opus"):
		return 4096
	case model == "claude-opus-4",
		strings.Contains(model, "claude-opus-4-0"),
		strings.Contains(model, "claude-opus-4-1"),
		strings.Contains(model, "claude-opus-4-2025"):
		return 32000
	case model == "claude-sonnet-4",
		strings.Contains(model, "claude-sonnet-4-0"),
		strings.Contains(model, "claude-sonnet-4-2025"),
		strings.Contains(model, "claude-sonnet-4-5"),
		strings.Contains(model, "claude-opus-4-5"):
		return 64000
	default:
		if model != "" {
			return 128000
		}
		return 0
	}
}

func ensureClaudeCodeMaxTokens(body []byte, modelID string) []byte {
	defaultMax := claudeCodeDefaultMaxTokens(modelID)
	upperLimit := claudeCodeMaxTokensUpperLimit(modelID)
	if defaultMax <= 0 || upperLimit <= 0 || len(body) == 0 || !gjson.ValidBytes(body) {
		return body
	}
	maxTokens := defaultMax
	if requested := gjson.GetBytes(body, "max_tokens"); requested.Type == gjson.Number {
		if requestedMax := int(requested.Int()); requestedMax > 0 {
			maxTokens = requestedMax
		}
	}
	if maxTokens > upperLimit {
		maxTokens = upperLimit
	}
	body, _ = sjson.SetBytes(body, "max_tokens", maxTokens)
	return body
}
