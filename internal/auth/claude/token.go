// Package claude provides authentication and token management functionality
// for Anthropic's Claude AI services. It handles OAuth2 token storage, serialization,
// and retrieval for maintaining authenticated sessions with the Claude API.
package claude

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
)

// TokenFileName returns a collision-resistant credential filename without
// exposing the OAuth access token.
func (ts *ClaudeTokenStorage) TokenFileName() (string, error) {
	if ts == nil {
		return "", fmt.Errorf("Claude token storage is nil")
	}
	identity := strings.TrimSpace(ts.Email)
	if identity == "" {
		identity = strings.TrimSpace(ts.AccountUUID)
	}
	if identity == "" {
		accessToken := strings.TrimSpace(ts.AccessToken)
		if accessToken == "" {
			return "", fmt.Errorf("Claude token storage is missing account identity")
		}
		digest := sha256.Sum256([]byte(accessToken))
		identity = fmt.Sprintf("oauth-%x", digest[:8])
	}
	identity = strings.NewReplacer("/", "_", "\\", "_").Replace(identity)
	return "claude-" + identity + ".json", nil
}

// ClaudeTokenStorage stores OAuth2 token information for Anthropic Claude API authentication.
// It maintains compatibility with the existing auth system while adding Claude-specific fields
// for managing access tokens, refresh tokens, and user account information.
type ClaudeTokenStorage struct {
	// IDToken is the JWT ID token containing user claims and identity information.
	IDToken string `json:"id_token"`

	// AccessToken is the OAuth2 access token used for authenticating API requests.
	AccessToken string `json:"access_token"`

	// RefreshToken is used to obtain new access tokens when the current one expires.
	RefreshToken string `json:"refresh_token"`

	// LastRefresh is the timestamp of the last token refresh operation.
	LastRefresh string `json:"last_refresh"`

	// Email is the Anthropic account email address associated with this token.
	Email string `json:"email"`

	// AccountUUID is the stable Anthropic account identifier returned by OAuth.
	AccountUUID string `json:"account_uuid"`

	// OrganizationUUID is the stable Anthropic organization identifier returned by OAuth.
	OrganizationUUID string `json:"organization_uuid"`

	// Scopes is the OAuth scope list persisted by Claude Code credentials.
	Scopes []string `json:"scopes,omitempty"`

	// RefreshTokenExpiresAt is stored as Unix milliseconds because that is the
	// representation used by Claude Code's rotating OAuth credentials.
	RefreshTokenExpiresAt int64 `json:"refresh_token_expires_at,omitempty"`

	// SubscriptionType and RateLimitTier come from /api/oauth/profile.
	SubscriptionType string `json:"subscription_type,omitempty"`
	RateLimitTier    string `json:"rate_limit_tier,omitempty"`

	// ClientID is present only for custom OAuth clients.
	ClientID string `json:"client_id,omitempty"`

	// Type indicates the authentication provider type, always "claude" for this storage.
	Type string `json:"type"`

	// Expire is the timestamp when the current access token expires.
	Expire string `json:"expired"`

	// Metadata holds arbitrary key-value pairs injected via hooks.
	// It is not exported to JSON directly to allow flattening during serialization.
	Metadata map[string]any `json:"-"`
}

// Clone returns an independent token storage value for refresh-time mutation.
func (ts *ClaudeTokenStorage) Clone() *ClaudeTokenStorage {
	if ts == nil {
		return nil
	}
	cloned := *ts
	if len(ts.Metadata) > 0 {
		cloned.Metadata = make(map[string]any, len(ts.Metadata))
		for key, value := range ts.Metadata {
			cloned.Metadata[key] = value
		}
	}
	cloned.Scopes = append([]string(nil), ts.Scopes...)
	return &cloned
}

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (ts *ClaudeTokenStorage) SetMetadata(meta map[string]any) {
	ts.Metadata = meta
}

// DecodeTokenStorage accepts both CLIProxyAPI's flat credential files and
// Claude Code's native {"claudeAiOauth": {...}} credential envelope.
func DecodeTokenStorage(payload []byte) (*ClaudeTokenStorage, map[string]any, bool, error) {
	var metadata map[string]any
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return nil, nil, false, err
	}

	if nested, ok := metadata["claudeAiOauth"].(map[string]any); ok {
		storage := &ClaudeTokenStorage{
			AccessToken:           stringValue(nested, "accessToken"),
			RefreshToken:          stringValue(nested, "refreshToken"),
			Scopes:                stringSliceValue(nested["scopes"]),
			RefreshTokenExpiresAt: int64Value(nested, "refreshTokenExpiresAt"),
			SubscriptionType:      stringValue(nested, "subscriptionType"),
			RateLimitTier:         stringValue(nested, "rateLimitTier"),
			ClientID:              stringValue(nested, "clientId"),
			Type:                  "claude",
		}
		if expiresAt := int64Value(nested, "expiresAt"); expiresAt > 0 {
			storage.Expire = time.UnixMilli(expiresAt).UTC().Format(time.RFC3339Nano)
		}
		metadata["type"] = "claude"
		metadata["access_token"] = storage.AccessToken
		metadata["refresh_token"] = storage.RefreshToken
		metadata["expired"] = storage.Expire
		metadata["scopes"] = append([]string(nil), storage.Scopes...)
		metadata["refresh_token_expires_at"] = storage.RefreshTokenExpiresAt
		metadata["subscription_type"] = storage.SubscriptionType
		metadata["rate_limit_tier"] = storage.RateLimitTier
		metadata["client_id"] = storage.ClientID
		storage.Metadata = metadata
		return storage, metadata, true, nil
	}

	var storage ClaudeTokenStorage
	if err := json.Unmarshal(payload, &storage); err != nil {
		return nil, nil, false, err
	}
	storage.Metadata = metadata
	return &storage, metadata, false, nil
}

func stringValue(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return strings.TrimSpace(value)
}

func int64Value(object map[string]any, key string) int64 {
	switch value := object[key].(type) {
	case float64:
		return int64(value)
	case int64:
		return value
	case int:
		return int64(value)
	case json.Number:
		parsed, _ := value.Int64()
		return parsed
	case string:
		parsed, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		return parsed
	default:
		return 0
	}
}

func stringSliceValue(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
		return out
	case string:
		return strings.Fields(typed)
	default:
		return nil
	}
}

// SaveTokenToFile serializes the Claude token storage to a JSON file.
// This method creates the necessary directory structure and writes the token
// data in JSON format to the specified file path for persistent storage.
// It merges any injected metadata into the top-level JSON object.
//
// Parameters:
//   - authFilePath: The full path where the token file should be saved
//
// Returns:
//   - error: An error if the operation fails, nil otherwise
func (ts *ClaudeTokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "claude"

	// Merge metadata using helper
	data, errMerge := misc.MergeMetadata(ts, ts.Metadata)
	if errMerge != nil {
		return fmt.Errorf("failed to merge metadata: %w", errMerge)
	}
	// Typed OAuth fields are authoritative. Metadata may contain a stale copy
	// loaded from an older credential file and must not roll back a refresh.
	data["id_token"] = ts.IDToken
	data["access_token"] = ts.AccessToken
	data["refresh_token"] = ts.RefreshToken
	data["last_refresh"] = ts.LastRefresh
	data["email"] = ts.Email
	data["account_uuid"] = ts.AccountUUID
	data["organization_uuid"] = ts.OrganizationUUID
	data["scopes"] = append([]string(nil), ts.Scopes...)
	data["refresh_token_expires_at"] = ts.RefreshTokenExpiresAt
	data["subscription_type"] = ts.SubscriptionType
	data["rate_limit_tier"] = ts.RateLimitTier
	data["client_id"] = ts.ClientID
	data["type"] = ts.Type
	data["expired"] = ts.Expire

	// Serialize the complete payload before touching the destination. In
	// particular, invalid hook metadata must not truncate a valid credential.
	payload, errMarshal := json.Marshal(data)
	if errMarshal != nil {
		return fmt.Errorf("failed to encode token data: %w", errMarshal)
	}
	return saveClaudeCredentialPayload(authFilePath, append(payload, '\n'))
}

// SaveOfficialTokenToFile updates Claude Code's native credential envelope
// without changing unrelated top-level fields in the file.
func (ts *ClaudeTokenStorage) SaveOfficialTokenToFile(authFilePath string, envelope map[string]any) error {
	misc.LogSavingCredentials(authFilePath)
	data := make(map[string]any, len(envelope)+1)
	for key, value := range envelope {
		data[key] = value
	}
	for _, key := range []string{
		"type", "access_token", "refresh_token", "expired", "scopes",
		"refresh_token_expires_at", "subscription_type", "rate_limit_tier", "client_id",
	} {
		delete(data, key)
	}
	nested := make(map[string]any)
	if existing, ok := data["claudeAiOauth"].(map[string]any); ok {
		for key, value := range existing {
			nested[key] = value
		}
	}
	nested["accessToken"] = ts.AccessToken
	nested["refreshToken"] = ts.RefreshToken
	if ts.Expire == "" {
		nested["expiresAt"] = int64(0)
	} else if expiresAt, errParse := time.Parse(time.RFC3339, ts.Expire); errParse == nil {
		nested["expiresAt"] = expiresAt.UnixMilli()
	} else {
		return fmt.Errorf("failed to parse Claude OAuth access-token expiry: %w", errParse)
	}
	nested["scopes"] = append([]string(nil), ts.Scopes...)
	if ts.RefreshTokenExpiresAt > 0 {
		nested["refreshTokenExpiresAt"] = ts.RefreshTokenExpiresAt
	} else {
		delete(nested, "refreshTokenExpiresAt")
	}
	if ts.SubscriptionType != "" {
		nested["subscriptionType"] = ts.SubscriptionType
	} else {
		delete(nested, "subscriptionType")
	}
	if ts.RateLimitTier != "" {
		nested["rateLimitTier"] = ts.RateLimitTier
	} else {
		delete(nested, "rateLimitTier")
	}
	if ts.ClientID != "" {
		nested["clientId"] = ts.ClientID
	} else {
		delete(nested, "clientId")
	}
	data["claudeAiOauth"] = nested

	payload, errMarshal := json.Marshal(data)
	if errMarshal != nil {
		return fmt.Errorf("failed to encode token data: %w", errMarshal)
	}
	return saveClaudeCredentialPayload(authFilePath, append(payload, '\n'))
}

func saveClaudeCredentialPayload(authFilePath string, payload []byte) error {

	dir := filepath.Dir(authFilePath)
	if errMkdir := os.MkdirAll(dir, 0700); errMkdir != nil {
		return fmt.Errorf("failed to create directory: %w", errMkdir)
	}

	// Write a same-directory temporary file so Rename remains an atomic
	// replacement on filesystems that provide normal rename semantics.
	tempFile, errCreate := os.CreateTemp(dir, "."+filepath.Base(authFilePath)+".tmp-*")
	if errCreate != nil {
		return fmt.Errorf("failed to create temporary token file: %w", errCreate)
	}
	tempPath := tempFile.Name()
	defer func() {
		if tempPath != "" {
			_ = tempFile.Close()
			_ = os.Remove(tempPath)
		}
	}()

	if errChmod := tempFile.Chmod(0600); errChmod != nil {
		return fmt.Errorf("failed to secure temporary token file: %w", errChmod)
	}
	written, errWrite := tempFile.Write(payload)
	if errWrite != nil {
		return fmt.Errorf("failed to write temporary token file: %w", errWrite)
	}
	if written != len(payload) {
		return fmt.Errorf("failed to write temporary token file: %w", io.ErrShortWrite)
	}
	if errSync := tempFile.Sync(); errSync != nil {
		return fmt.Errorf("failed to sync temporary token file: %w", errSync)
	}
	if errClose := tempFile.Close(); errClose != nil {
		return fmt.Errorf("failed to close temporary token file: %w", errClose)
	}
	if errRename := atomicReplaceFile(tempPath, authFilePath); errRename != nil {
		return fmt.Errorf("failed to replace token file: %w", errRename)
	}
	tempPath = ""

	// Persist the directory entry when supported. Some platforms do not allow
	// syncing directory handles, so this is deliberately best effort.
	if dirFile, errOpenDir := os.Open(dir); errOpenDir == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}

	return nil
}
