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

type sessionIDCacheEntry struct {
	value  string
	expire time.Time
}

var (
	sessionIDCache            = make(map[string]sessionIDCacheEntry)
	sessionIDCacheMu          sync.RWMutex
	sessionIDCacheCleanupOnce sync.Once
)

type claudeIDKVClient interface {
	KVGet(ctx context.Context, key string) ([]byte, bool, error)
	KVSetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	KVCompareAndSwap(ctx context.Context, key string, expected []byte, expectedExists bool, value []byte, ttl time.Duration) (bool, error)
	KVExpire(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

var currentClaudeIDKVClient = func() (claudeIDKVClient, bool, error) {
	return homekv.CurrentKVClient()
}

const (
	sessionIDTTL                = time.Hour
	sessionIDCacheCleanupPeriod = 15 * time.Minute
	claudeIDKVMaxAttempts       = 8
)

func startSessionIDCacheCleanup() {
	go func() {
		ticker := time.NewTicker(sessionIDCacheCleanupPeriod)
		defer ticker.Stop()
		for range ticker.C {
			purgeExpiredSessionIDs()
		}
	}()
}

func purgeExpiredSessionIDs() {
	now := time.Now()
	sessionIDCacheMu.Lock()
	for key, entry := range sessionIDCache {
		if !entry.expire.After(now) {
			delete(sessionIDCache, key)
		}
	}
	sessionIDCacheMu.Unlock()
}

func sessionIDCacheKey(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

// CachedSessionID returns a stable session UUID per apiKey, refreshing the TTL on each access.
func CachedSessionID(apiKey string) string {
	value, errValue := CachedSessionIDRequired(context.Background(), apiKey)
	if errValue == nil && value != "" {
		return value
	}
	value, _ = generateClaudeCodeSessionIDRequired()
	return value
}

// CachedSessionIDRequired returns a stable session UUID per apiKey for request-time paths.
func CachedSessionIDRequired(ctx context.Context, apiKey string) (string, error) {
	if apiKey == "" {
		return generateClaudeCodeSessionIDRequired()
	}
	client, homeMode, errClient := currentClaudeIDKVClient()
	if homeMode {
		if errClient != nil {
			return "", errClient
		}
		return resolveCachedClaudeIDKVValue(
			ctx,
			client,
			claudeSessionIDKVKey(apiKey),
			sessionIDTTL,
			"session ID",
			isValidClaudeCodeUUID,
			generateClaudeCodeSessionIDRequired,
		)
	}

	sessionIDCacheCleanupOnce.Do(startSessionIDCacheCleanup)

	key := sessionIDCacheKey(apiKey)
	now := time.Now()

	sessionIDCacheMu.RLock()
	entry, ok := sessionIDCache[key]
	valid := ok && entry.value != "" && entry.expire.After(now) && isValidClaudeCodeUUID(entry.value)
	sessionIDCacheMu.RUnlock()
	if valid {
		sessionIDCacheMu.Lock()
		entry = sessionIDCache[key]
		if entry.value != "" && entry.expire.After(now) && isValidClaudeCodeUUID(entry.value) {
			entry.expire = now.Add(sessionIDTTL)
			sessionIDCache[key] = entry
			sessionIDCacheMu.Unlock()
			return entry.value, nil
		}
		sessionIDCacheMu.Unlock()
	}

	newID, errNewID := generateClaudeCodeSessionIDRequired()
	if errNewID != nil {
		return "", errNewID
	}

	sessionIDCacheMu.Lock()
	entry, ok = sessionIDCache[key]
	if !ok || entry.value == "" || !entry.expire.After(now) || !isValidClaudeCodeUUID(entry.value) {
		entry.value = newID
	}
	entry.expire = now.Add(sessionIDTTL)
	sessionIDCache[key] = entry
	sessionIDCacheMu.Unlock()
	return entry.value, nil
}

func resolveCachedClaudeIDKVValue(
	ctx context.Context,
	client claudeIDKVClient,
	key string,
	ttl time.Duration,
	label string,
	validator func(string) bool,
	generator func() (string, error),
) (string, error) {
	for attempt := 0; attempt < claudeIDKVMaxAttempts; attempt++ {
		raw, found, errGet := client.KVGet(ctx, key)
		if errGet != nil {
			return "", errGet
		}
		rawValue := string(raw)
		current := strings.TrimSpace(rawValue)
		if found && rawValue == current && validator(current) {
			refreshed, errExpire := client.KVExpire(ctx, key, ttl)
			if errExpire != nil {
				return "", errExpire
			}
			if refreshed {
				return current, nil
			}
			continue
		}

		candidate, errGenerate := generator()
		if errGenerate != nil {
			return "", errGenerate
		}
		var written bool
		var errWrite error
		if found {
			written, errWrite = client.KVCompareAndSwap(ctx, key, raw, true, []byte(candidate), ttl)
		} else {
			written, errWrite = client.KVSetNX(ctx, key, []byte(candidate), ttl)
		}
		if errWrite != nil {
			return "", errWrite
		}

		verifiedRaw, verifiedFound, errVerify := client.KVGet(ctx, key)
		if errVerify != nil {
			return "", errVerify
		}
		verified := strings.TrimSpace(string(verifiedRaw))
		if verifiedFound && validator(verified) {
			return verified, nil
		}
		if written {
			return "", fmt.Errorf("home kv Claude %s missing after write", label)
		}
	}
	return "", fmt.Errorf("home kv Claude %s did not converge after concurrent updates", label)
}

func claudeSessionIDKVKey(apiKey string) string {
	return "cpa:claude:session-id:" + homekv.HashKeyPart(apiKey)
}
