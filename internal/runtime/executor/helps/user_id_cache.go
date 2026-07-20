package helps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
)

const (
	userIDTTL                = time.Hour
	userIDCacheCleanupPeriod = 15 * time.Minute
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
	return generateFakeUserID()
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
	return buildClaudeCodeUserID(deviceID, "", sessionID), nil
}

// CachedClaudeCodeDeviceIDRequired returns a stable Claude Code device_id per apiKey.
func CachedClaudeCodeDeviceIDRequired(ctx context.Context, apiKey string) (string, error) {
	if apiKey == "" {
		return generateClaudeCodeDeviceID(), nil
	}
	client, homeMode, errClient := currentClaudeIDKVClient()
	if homeMode {
		if errClient != nil {
			return "", errClient
		}
		key := claudeUserIDKVKey(apiKey)
		raw, found, errGet := client.KVGet(ctx, key)
		if errGet != nil {
			return "", errGet
		}
		if found && isValidClaudeCodeDeviceID(strings.TrimSpace(string(raw))) {
			if _, errExpire := client.KVExpire(ctx, key, userIDTTL); errExpire != nil {
				return "", errExpire
			}
			return strings.TrimSpace(string(raw)), nil
		}
		newDeviceID := generateClaudeCodeDeviceID()
		if found {
			written, errSet := client.KVSet(ctx, key, []byte(newDeviceID), homekv.KVSetOptions{EX: userIDTTL})
			if errSet != nil {
				return "", errSet
			}
			if !written {
				return "", fmt.Errorf("home kv Claude device id missing after invalid value replacement")
			}
			return newDeviceID, nil
		}
		if _, errSet := client.KVSetNX(ctx, key, []byte(newDeviceID), userIDTTL); errSet != nil {
			return "", errSet
		}
		raw, found, errGet = client.KVGet(ctx, key)
		if errGet != nil {
			return "", errGet
		}
		if found && isValidClaudeCodeDeviceID(strings.TrimSpace(string(raw))) {
			return strings.TrimSpace(string(raw)), nil
		}
		return "", fmt.Errorf("home kv Claude device id missing after set")
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

	newDeviceID := generateClaudeCodeDeviceID()

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

func claudeUserIDKVKey(apiKey string) string {
	return "cpa:claude:device-id:" + homekv.HashKeyPart(apiKey)
}
