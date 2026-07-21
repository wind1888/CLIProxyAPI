package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const claudeOAuthRefreshLockRetry = 100 * time.Millisecond

type claudeOAuthRefreshFileLock struct {
	lock *flock.Flock
}

func claudeOAuthCredentialPath(cfg *config.Config, auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	name := strings.TrimSpace(auth.FileName)
	if name == "" && auth.Attributes != nil {
		name = strings.TrimSpace(auth.Attributes["path"])
	}
	if name == "" {
		return ""
	}
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	if cfg == nil || strings.TrimSpace(cfg.AuthDir) == "" {
		return ""
	}
	return filepath.Join(cfg.AuthDir, name)
}

func acquireClaudeOAuthRefreshFileLock(ctx context.Context, credentialPath string) (*claudeOAuthRefreshFileLock, error) {
	credentialPath = strings.TrimSpace(credentialPath)
	if credentialPath == "" {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dir := filepath.Dir(credentialPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create Claude OAuth credential directory: %w", err)
	}
	lockPath := credentialPath + ".oauth_refresh.lock"
	fileLock := flock.New(lockPath, flock.SetPermissions(0600))
	locked, errLock := fileLock.TryLockContext(ctx, claudeOAuthRefreshLockRetry)
	if errLock != nil {
		_ = fileLock.Close()
		return nil, fmt.Errorf("acquire Claude OAuth refresh lock: %w", errLock)
	}
	if !locked {
		_ = fileLock.Close()
		return nil, fmt.Errorf("acquire Claude OAuth refresh lock: lock was not acquired")
	}
	return &claudeOAuthRefreshFileLock{lock: fileLock}, nil
}

func (lock *claudeOAuthRefreshFileLock) release() {
	if lock == nil {
		return
	}
	if lock.lock != nil {
		_ = lock.lock.Close()
	}
}

func readClaudeOAuthCredential(path string) (*claudeauth.ClaudeTokenStorage, map[string]any, error) {
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		return nil, nil, errRead
	}
	storage, metadata, _, errDecode := claudeauth.DecodeTokenStorage(raw)
	return storage, metadata, errDecode
}

func claudeMetadataInt64(metadata map[string]any, keys ...string) int64 {
	for _, key := range keys {
		switch value := metadata[key].(type) {
		case float64:
			return int64(value)
		case int64:
			return value
		case int:
			return int64(value)
		case json.Number:
			if parsed, err := value.Int64(); err == nil {
				return parsed
			}
		case string:
			if parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func hydrateClaudeOAuthStorageAliases(storage *claudeauth.ClaudeTokenStorage, metadata map[string]any) {
	if storage == nil {
		return
	}
	if storage.RefreshTokenExpiresAt == 0 {
		storage.RefreshTokenExpiresAt = claudeMetadataInt64(metadata, "refreshTokenExpiresAt", "refresh_token_expires_at")
	}
	if storage.SubscriptionType == "" {
		storage.SubscriptionType = firstNonEmptyMetadataString(metadata, "subscriptionType", "subscription_type")
	}
	if storage.RateLimitTier == "" {
		storage.RateLimitTier = firstNonEmptyMetadataString(metadata, "rateLimitTier", "rate_limit_tier")
	}
	if storage.ClientID == "" {
		storage.ClientID = firstNonEmptyMetadataString(metadata, "clientId", "client_id")
	}
}

func firstNonEmptyMetadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := metadata[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func adoptClaudeOAuthCredential(auth *cliproxyauth.Auth, storage *claudeauth.ClaudeTokenStorage, diskMetadata map[string]any) {
	if auth == nil || storage == nil {
		return
	}
	hydrateClaudeOAuthStorageAliases(storage, diskMetadata)
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	for key, value := range diskMetadata {
		auth.Metadata[key] = value
	}
	auth.Metadata["access_token"] = storage.AccessToken
	auth.Metadata["refresh_token"] = storage.RefreshToken
	auth.Metadata["expired"] = storage.Expire
	auth.Metadata["scopes"] = append([]string(nil), storage.Scopes...)
	auth.Metadata["subscription_type"] = storage.SubscriptionType
	auth.Metadata["rate_limit_tier"] = storage.RateLimitTier
	auth.Metadata["refresh_token_expires_at"] = storage.RefreshTokenExpiresAt
	auth.Metadata["client_id"] = storage.ClientID
	storage.SetMetadata(auth.Metadata)
	auth.Storage = storage
}

func persistClaudeOAuthCredential(path string, auth *cliproxyauth.Auth) error {
	if strings.TrimSpace(path) == "" || auth == nil {
		return nil
	}
	storage, ok := auth.Storage.(*claudeauth.ClaudeTokenStorage)
	if !ok || storage == nil {
		return fmt.Errorf("Claude OAuth token storage is unavailable")
	}
	storage.SetMetadata(auth.Metadata)
	raw, errRead := os.ReadFile(path)
	if errRead == nil {
		_, envelope, official, errDecode := claudeauth.DecodeTokenStorage(raw)
		if errDecode != nil {
			return fmt.Errorf("decode existing Claude OAuth credential: %w", errDecode)
		}
		if official {
			return storage.SaveOfficialTokenToFile(path, envelope)
		}
	} else if !os.IsNotExist(errRead) {
		return fmt.Errorf("read existing Claude OAuth credential: %w", errRead)
	}
	return storage.SaveTokenToFile(path)
}
