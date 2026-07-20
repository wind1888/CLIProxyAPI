// Package claude provides authentication and token management functionality
// for Anthropic's Claude AI services. It handles OAuth2 token storage, serialization,
// and retrieval for maintaining authenticated sessions with the Claude API.
package claude

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	// Type indicates the authentication provider type, always "claude" for this storage.
	Type string `json:"type"`

	// Expire is the timestamp when the current access token expires.
	Expire string `json:"expired"`

	// Metadata holds arbitrary key-value pairs injected via hooks.
	// It is not exported to JSON directly to allow flattening during serialization.
	Metadata map[string]any `json:"-"`
}

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (ts *ClaudeTokenStorage) SetMetadata(meta map[string]any) {
	ts.Metadata = meta
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

	// Create directory structure if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(authFilePath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Create the token file
	f, err := os.Create(authFilePath)
	if err != nil {
		return fmt.Errorf("failed to create token file: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

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
	data["type"] = ts.Type
	data["expired"] = ts.Expire

	// Encode and write the token data as JSON
	if err = json.NewEncoder(f).Encode(data); err != nil {
		return fmt.Errorf("failed to write token to file: %w", err)
	}
	return nil
}
