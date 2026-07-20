package helps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	homekv "github.com/router-for-me/CLIProxyAPI/v7/internal/home"
)

type userIDCacheEntry struct {
	value  string
	expire time.Time
}

var (
	userIDCache            = make(map[string]userIDCacheEntry)
	userIDCacheMu          sync.RWMutex
	userIDCacheCleanupOnce sync.Once
	installationDeviceMu   sync.Mutex
)

const (
	// Claude Code persists .claude.json.userID for the lifetime of an
	// installation. A long renewable horizon models that persistence while
	// retaining bounded cleanup for abandoned proxy installations.
	userIDTTL                = 10 * 365 * 24 * time.Hour
	userIDCacheCleanupPeriod = 24 * time.Hour
)

func startUserIDCacheCleanup() {
	go func() {
		ticker := time.NewTicker(userIDCacheCleanupPeriod)
		defer ticker.Stop()
		for range ticker.C {
			purgeExpiredUserIDs()
		}
	}()
}

func purgeExpiredUserIDs() {
	now := time.Now()
	userIDCacheMu.Lock()
	for key, entry := range userIDCache {
		if !entry.expire.After(now) {
			delete(userIDCache, key)
		}
	}
	userIDCacheMu.Unlock()
}

func userIDCacheKey(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

func CachedUserID(apiKey string) string {
	value, errValue := CachedUserIDRequired(context.Background(), apiKey)
	if errValue == nil && value != "" {
		return value
	}
	value, _ = generateFakeUserIDRequired()
	return value
}

// CachedUserIDRequired returns Claude Code's metadata.user_id string using a
// stable per-apiKey device_id and the current per-apiKey session_id.
func CachedUserIDRequired(ctx context.Context, apiKey string) (string, error) {
	sessionID, errSessionID := CachedSessionIDRequired(ctx, apiKey)
	if errSessionID != nil {
		return "", errSessionID
	}
	deviceID, errDeviceID := CachedClaudeCodeDeviceIDRequired(ctx, apiKey)
	if errDeviceID != nil {
		return "", errDeviceID
	}
	return buildClaudeCodeUserIDRequired(deviceID, "", sessionID)
}

// CachedClaudeCodeDeviceIDRequired returns a stable Claude Code device_id per apiKey.
func CachedClaudeCodeDeviceIDRequired(ctx context.Context, apiKey string) (string, error) {
	if apiKey == "" {
		return generateClaudeCodeDeviceIDRequired()
	}
	client, homeMode, errClient := currentClaudeIDKVClient()
	if homeMode {
		if errClient != nil {
			return "", errClient
		}
		return resolveCachedClaudeIDKVValue(
			ctx,
			client,
			claudeUserIDKVKey(apiKey),
			userIDTTL,
			"device ID",
			isValidClaudeCodeDeviceID,
			generateClaudeCodeDeviceIDRequired,
		)
	}

	userIDCacheCleanupOnce.Do(startUserIDCacheCleanup)

	key := userIDCacheKey(apiKey)
	now := time.Now()

	userIDCacheMu.RLock()
	entry, ok := userIDCache[key]
	valid := ok && entry.value != "" && entry.expire.After(now) && isValidClaudeCodeDeviceID(entry.value)
	userIDCacheMu.RUnlock()
	if valid {
		userIDCacheMu.Lock()
		entry = userIDCache[key]
		if entry.value != "" && entry.expire.After(now) && isValidClaudeCodeDeviceID(entry.value) {
			entry.expire = now.Add(userIDTTL)
			userIDCache[key] = entry
			userIDCacheMu.Unlock()
			return entry.value, nil
		}
		userIDCacheMu.Unlock()
	}

	newDeviceID, errNewDeviceID := generateClaudeCodeDeviceIDRequired()
	if errNewDeviceID != nil {
		return "", errNewDeviceID
	}

	userIDCacheMu.Lock()
	entry, ok = userIDCache[key]
	if !ok || entry.value == "" || !entry.expire.After(now) || !isValidClaudeCodeDeviceID(entry.value) {
		entry.value = newDeviceID
	}
	entry.expire = now.Add(userIDTTL)
	userIDCache[key] = entry
	userIDCacheMu.Unlock()
	return entry.value, nil
}

// CachedClaudeCodeInstallationDeviceIDRequired persists the synthetic SDK
// device identity in the configured auth directory when Home KV is not active.
func CachedClaudeCodeInstallationDeviceIDRequired(ctx context.Context, identityScope, authDir string) (string, error) {
	client, homeMode, errClient := currentClaudeIDKVClient()
	if homeMode {
		if errClient != nil {
			return "", errClient
		}
		return resolveCachedClaudeIDKVValue(
			ctx,
			client,
			claudeUserIDKVKey(identityScope),
			userIDTTL,
			"device ID",
			isValidClaudeCodeDeviceID,
			generateClaudeCodeDeviceIDRequired,
		)
	}
	authDir = strings.TrimSpace(authDir)
	if authDir == "" {
		return CachedClaudeCodeDeviceIDRequired(ctx, identityScope)
	}

	installationDeviceMu.Lock()
	defer installationDeviceMu.Unlock()
	if errMkdir := os.MkdirAll(authDir, 0o700); errMkdir != nil {
		return "", fmt.Errorf("create Claude identity directory: %w", errMkdir)
	}
	path := filepath.Join(authDir, ".claude-device-id")
	if value, errRead := readClaudeInstallationDeviceID(path); errRead == nil {
		return value, nil
	} else if !errors.Is(errRead, os.ErrNotExist) {
		return "", errRead
	}

	deviceID, errGenerate := generateClaudeCodeDeviceIDRequired()
	if errGenerate != nil {
		return "", errGenerate
	}
	file, errOpen := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(errOpen, os.ErrExist) {
		return readClaudeInstallationDeviceID(path)
	}
	if errOpen != nil {
		return "", fmt.Errorf("create Claude installation device ID: %w", errOpen)
	}
	if _, errWrite := file.WriteString(deviceID + "\n"); errWrite != nil {
		_ = file.Close()
		return "", fmt.Errorf("write Claude installation device ID: %w", errWrite)
	}
	if errSync := file.Sync(); errSync != nil {
		_ = file.Close()
		return "", fmt.Errorf("sync Claude installation device ID: %w", errSync)
	}
	if errClose := file.Close(); errClose != nil {
		return "", fmt.Errorf("close Claude installation device ID: %w", errClose)
	}
	return deviceID, nil
}

func readClaudeInstallationDeviceID(path string) (string, error) {
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		return "", errRead
	}
	deviceID := strings.TrimSpace(string(raw))
	if !isValidClaudeCodeDeviceID(deviceID) {
		return "", fmt.Errorf("invalid Claude installation device ID file")
	}
	return deviceID, nil
}

func claudeUserIDKVKey(apiKey string) string {
	return "cpa:claude:device-id:" + homekv.HashKeyPart(apiKey)
}
