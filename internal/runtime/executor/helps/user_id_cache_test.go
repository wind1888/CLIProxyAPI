package helps

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tidwall/gjson"
)

func resetUserIDCache() {
	userIDCacheMu.Lock()
	userIDCache = make(map[string]userIDCacheEntry)
	userIDCacheMu.Unlock()
}

func TestCachedUserID_ReusesWithinTTL(t *testing.T) {
	resetUserIDCache()
	resetSessionIDCache()

	first := CachedUserID("api-key-1")
	second := CachedUserID("api-key-1")

	if first == "" {
		t.Fatal("expected generated user_id to be non-empty")
	}
	if first != second {
		t.Fatalf("expected cached user_id to be reused, got %q and %q", first, second)
	}
}

func TestCachedUserID_ExpiresAfterTTL(t *testing.T) {
	resetUserIDCache()
	resetSessionIDCache()

	expiredID := CachedUserID("api-key-expired")
	expiredDeviceID := gjson.Get(expiredID, "device_id").String()
	cacheKey := userIDCacheKey("api-key-expired")
	userIDCacheMu.Lock()
	userIDCache[cacheKey] = userIDCacheEntry{
		value:  expiredDeviceID,
		expire: time.Now().Add(-time.Minute),
	}
	userIDCacheMu.Unlock()

	newID := CachedUserID("api-key-expired")
	if newID == expiredID {
		t.Fatalf("expected expired user_id to be replaced, got %q", newID)
	}
	if newID == "" {
		t.Fatal("expected regenerated user_id to be non-empty")
	}
}

func TestCachedUserID_IsScopedByAPIKey(t *testing.T) {
	resetUserIDCache()
	resetSessionIDCache()

	first := CachedUserID("api-key-1")
	second := CachedUserID("api-key-2")

	if first == second {
		t.Fatalf("expected different API keys to have different user_ids, got %q", first)
	}
}

func TestCachedUserID_RenewsTTLOnHit(t *testing.T) {
	resetUserIDCache()
	resetSessionIDCache()

	key := "api-key-renew"
	id := CachedUserID(key)
	deviceID := gjson.Get(id, "device_id").String()
	cacheKey := userIDCacheKey(key)

	soon := time.Now()
	userIDCacheMu.Lock()
	userIDCache[cacheKey] = userIDCacheEntry{
		value:  deviceID,
		expire: soon.Add(2 * time.Second),
	}
	userIDCacheMu.Unlock()

	if refreshed := CachedUserID(key); refreshed != id {
		t.Fatalf("expected cached user_id to be reused before expiry, got %q", refreshed)
	}

	userIDCacheMu.RLock()
	entry := userIDCache[cacheKey]
	userIDCacheMu.RUnlock()

	if entry.expire.Sub(soon) < 30*time.Minute {
		t.Fatalf("expected TTL to renew, got %v remaining", entry.expire.Sub(soon))
	}
}

func TestCachedUserIDRequiredHomeReusesKVAcrossLocalCacheReset(t *testing.T) {
	resetUserIDCache()
	resetSessionIDCache()
	client := newFakeClaudeIDKVClient()
	useFakeClaudeIDKVClient(t, client, true, nil)

	first, errFirst := CachedUserIDRequired(context.Background(), "api-key-1")
	if errFirst != nil {
		t.Fatalf("CachedUserIDRequired() first error = %v", errFirst)
	}
	resetUserIDCache()
	resetSessionIDCache()
	second, errSecond := CachedUserIDRequired(context.Background(), "api-key-1")
	if errSecond != nil {
		t.Fatalf("CachedUserIDRequired() second error = %v", errSecond)
	}
	if first != second {
		t.Fatalf("user id = %q then %q, want same Home KV value", first, second)
	}
	if !IsValidUserID(first) {
		t.Fatalf("user id %q is not valid", first)
	}
	if client.setCount != 2 {
		t.Fatalf("KVSetNX count = %d, want 2", client.setCount)
	}
	if client.expireCount != 2 || client.lastExpireTTL != userIDTTL {
		t.Fatalf("KVExpire count/ttl = %d/%v, want 2/%v", client.expireCount, client.lastExpireTTL, userIDTTL)
	}
	if client.lastSetTTL != userIDTTL {
		t.Fatalf("KVSetNX ttl = %v, want %v", client.lastSetTTL, userIDTTL)
	}
}

func TestCachedUserIDRequiredHomeReplacesInvalidDeviceIDKV(t *testing.T) {
	resetUserIDCache()
	resetSessionIDCache()
	client := newFakeClaudeIDKVClient()
	sessionKey := claudeSessionIDKVKey("api-key-1")
	deviceKey := claudeUserIDKVKey("api-key-1")
	client.values[sessionKey] = []byte("00000000-0000-4000-8000-000000000000")
	client.values[deviceKey] = []byte("not-a-device-id")
	useFakeClaudeIDKVClient(t, client, true, nil)

	value, errValue := CachedUserIDRequired(context.Background(), "api-key-1")
	if errValue != nil {
		t.Fatalf("CachedUserIDRequired() error = %v", errValue)
	}
	if !IsValidUserID(value) {
		t.Fatalf("replacement user id %q is not valid", value)
	}
	deviceID := gjson.Get(value, "device_id").String()
	if got := string(client.values[deviceKey]); got != deviceID {
		t.Fatalf("stored device id = %q, want replacement %q", got, deviceID)
	}
	if got := gjson.Get(value, "session_id").String(); got != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("session id = %q, want cached session", got)
	}
}

func TestCachedUserIDRequiredEmptyAPIKeyDoesNotUseHomeKV(t *testing.T) {
	client := newFakeClaudeIDKVClient()
	useFakeClaudeIDKVClient(t, client, true, nil)

	value, errValue := CachedUserIDRequired(context.Background(), "")
	if errValue != nil {
		t.Fatalf("CachedUserIDRequired(empty) error = %v", errValue)
	}
	if !IsValidUserID(value) {
		t.Fatalf("user id %q is not valid", value)
	}
	if client.getCount != 0 || client.setCount != 0 || client.expireCount != 0 {
		t.Fatalf("KV calls = get %d set %d expire %d, want all zero", client.getCount, client.setCount, client.expireCount)
	}
}

func TestCachedUserIDRequiredHomeKVFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client *fakeClaudeIDKVClient
	}{
		{name: "get", client: &fakeClaudeIDKVClient{values: make(map[string][]byte), getErr: errors.New("get failed")}},
		{name: "set", client: &fakeClaudeIDKVClient{values: make(map[string][]byte), setErr: errors.New("set failed")}},
		{name: "expire", client: &fakeClaudeIDKVClient{values: map[string][]byte{
			claudeSessionIDKVKey("api-key-1"): []byte("00000000-0000-4000-8000-000000000000"),
			claudeUserIDKVKey("api-key-1"):    []byte(GenerateClaudeCodeDeviceID()),
		}, expireErr: errors.New("expire failed")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useFakeClaudeIDKVClient(t, tc.client, true, nil)
			if _, errValue := CachedUserIDRequired(context.Background(), "api-key-1"); errValue == nil {
				t.Fatalf("CachedUserIDRequired() error = nil, want error")
			}
		})
	}
}

func TestCachedUserIDRequiredHomeRequiresReadAfterSet(t *testing.T) {
	client := newFakeClaudeIDKVClient()
	client.setNoPersist = true
	useFakeClaudeIDKVClient(t, client, true, nil)

	if _, errValue := CachedUserIDRequired(context.Background(), "api-key-1"); errValue == nil {
		t.Fatalf("CachedUserIDRequired() error = nil, want missing-after-set error")
	}
}
