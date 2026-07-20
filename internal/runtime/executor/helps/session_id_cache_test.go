package helps

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	homekv "github.com/router-for-me/CLIProxyAPI/v7/internal/home"
)

func resetSessionIDCache() {
	sessionIDCacheMu.Lock()
	sessionIDCache = make(map[string]sessionIDCacheEntry)
	sessionIDCacheMu.Unlock()
}

type fakeClaudeIDKVClient struct {
	mu            sync.Mutex
	values        map[string][]byte
	getErr        error
	setErr        error
	expireErr     error
	setNoPersist  bool
	expireFalse   bool
	getCount      int
	setCount      int
	expireCount   int
	lastSetTTL    time.Duration
	lastExpireTTL time.Duration
}

func newFakeClaudeIDKVClient() *fakeClaudeIDKVClient {
	return &fakeClaudeIDKVClient{values: make(map[string][]byte)}
}

func (c *fakeClaudeIDKVClient) KVGet(_ context.Context, key string) ([]byte, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getCount++
	if c.getErr != nil {
		return nil, false, c.getErr
	}
	value, ok := c.values[key]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), value...), true, nil
}

func (c *fakeClaudeIDKVClient) KVSet(_ context.Context, key string, value []byte, opts homekv.KVSetOptions) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setCount++
	if opts.EX > 0 {
		c.lastSetTTL = opts.EX
	} else {
		c.lastSetTTL = opts.PX
	}
	if c.setErr != nil {
		return false, c.setErr
	}
	if !c.setNoPersist {
		c.values[key] = append([]byte(nil), value...)
	}
	return true, nil
}

func (c *fakeClaudeIDKVClient) KVSetNX(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setCount++
	c.lastSetTTL = ttl
	if c.setErr != nil {
		return false, c.setErr
	}
	if _, ok := c.values[key]; ok {
		return false, nil
	}
	if !c.setNoPersist {
		c.values[key] = append([]byte(nil), value...)
	}
	return true, nil
}

func (c *fakeClaudeIDKVClient) KVCompareAndSwap(_ context.Context, key string, expected []byte, expectedExists bool, value []byte, ttl time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setCount++
	c.lastSetTTL = ttl
	if c.setErr != nil {
		return false, c.setErr
	}
	current, exists := c.values[key]
	if exists != expectedExists || (expectedExists && !bytes.Equal(current, expected)) {
		return false, nil
	}
	if !c.setNoPersist {
		c.values[key] = append([]byte(nil), value...)
	}
	return true, nil
}

func (c *fakeClaudeIDKVClient) KVExpire(_ context.Context, _ string, ttl time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireCount++
	c.lastExpireTTL = ttl
	if c.expireErr != nil {
		return false, c.expireErr
	}
	if c.expireFalse {
		return false, nil
	}
	return true, nil
}

func useFakeClaudeIDKVClient(t *testing.T, client *fakeClaudeIDKVClient, homeMode bool, errClient error) {
	t.Helper()
	previous := currentClaudeIDKVClient
	currentClaudeIDKVClient = func() (claudeIDKVClient, bool, error) {
		return client, homeMode, errClient
	}
	t.Cleanup(func() {
		currentClaudeIDKVClient = previous
	})
}

func TestCachedSessionIDRequiredHomeReusesKVAcrossLocalCacheReset(t *testing.T) {
	resetSessionIDCache()
	client := newFakeClaudeIDKVClient()
	useFakeClaudeIDKVClient(t, client, true, nil)

	first, errFirst := CachedSessionIDRequired(context.Background(), "api-key-1")
	if errFirst != nil {
		t.Fatalf("CachedSessionIDRequired() first error = %v", errFirst)
	}
	resetSessionIDCache()
	second, errSecond := CachedSessionIDRequired(context.Background(), "api-key-1")
	if errSecond != nil {
		t.Fatalf("CachedSessionIDRequired() second error = %v", errSecond)
	}
	if first != second {
		t.Fatalf("session id = %q then %q, want same Home KV value", first, second)
	}
	if _, errParse := uuid.Parse(first); errParse != nil {
		t.Fatalf("session id %q is not a UUID: %v", first, errParse)
	}
	if client.setCount != 1 {
		t.Fatalf("KVSetNX count = %d, want 1", client.setCount)
	}
	if client.expireCount != 1 || client.lastExpireTTL != sessionIDTTL {
		t.Fatalf("KVExpire count/ttl = %d/%v, want 1/%v", client.expireCount, client.lastExpireTTL, sessionIDTTL)
	}
	if client.lastSetTTL != sessionIDTTL {
		t.Fatalf("KVSetNX ttl = %v, want %v", client.lastSetTTL, sessionIDTTL)
	}
}

func TestCachedSessionIDRequiredHomeReplacesInvalidKV(t *testing.T) {
	resetSessionIDCache()
	client := newFakeClaudeIDKVClient()
	key := claudeSessionIDKVKey("api-key-1")
	client.values[key] = []byte("not-a-session-uuid")
	useFakeClaudeIDKVClient(t, client, true, nil)

	value, errValue := CachedSessionIDRequired(context.Background(), "api-key-1")
	if errValue != nil {
		t.Fatalf("CachedSessionIDRequired() error = %v", errValue)
	}
	if _, errParse := uuid.Parse(value); errParse != nil {
		t.Fatalf("replacement session id %q is not a UUID: %v", value, errParse)
	}
	if got := string(client.values[key]); got != value {
		t.Fatalf("stored session id = %q, want replacement %q", got, value)
	}
	if client.setCount != 1 {
		t.Fatalf("KVSet count = %d, want 1", client.setCount)
	}
	if client.expireCount != 0 {
		t.Fatalf("KVExpire count = %d, want 0 for invalid replacement", client.expireCount)
	}
	if client.lastSetTTL != sessionIDTTL {
		t.Fatalf("KVSet ttl = %v, want %v", client.lastSetTTL, sessionIDTTL)
	}
}

func TestCachedSessionIDRequiredEmptyAPIKeyDoesNotUseHomeKV(t *testing.T) {
	client := newFakeClaudeIDKVClient()
	useFakeClaudeIDKVClient(t, client, true, nil)

	value, errValue := CachedSessionIDRequired(context.Background(), "")
	if errValue != nil {
		t.Fatalf("CachedSessionIDRequired(empty) error = %v", errValue)
	}
	if _, errParse := uuid.Parse(value); errParse != nil {
		t.Fatalf("session id %q is not a UUID: %v", value, errParse)
	}
	if client.getCount != 0 || client.setCount != 0 || client.expireCount != 0 {
		t.Fatalf("KV calls = get %d set %d expire %d, want all zero", client.getCount, client.setCount, client.expireCount)
	}
}

func TestCachedSessionIDRequiredHomeKVFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client *fakeClaudeIDKVClient
	}{
		{name: "get", client: &fakeClaudeIDKVClient{values: make(map[string][]byte), getErr: errors.New("get failed")}},
		{name: "set", client: &fakeClaudeIDKVClient{values: make(map[string][]byte), setErr: errors.New("set failed")}},
		{name: "expire", client: &fakeClaudeIDKVClient{values: map[string][]byte{
			claudeSessionIDKVKey("api-key-1"): []byte(uuid.New().String()),
		}, expireErr: errors.New("expire failed")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useFakeClaudeIDKVClient(t, tc.client, true, nil)
			if _, errValue := CachedSessionIDRequired(context.Background(), "api-key-1"); errValue == nil {
				t.Fatalf("CachedSessionIDRequired() error = nil, want error")
			}
		})
	}
}

func TestCachedSessionIDRequiredHomeRequiresReadAfterSet(t *testing.T) {
	client := newFakeClaudeIDKVClient()
	client.setNoPersist = true
	useFakeClaudeIDKVClient(t, client, true, nil)

	if _, errValue := CachedSessionIDRequired(context.Background(), "api-key-1"); errValue == nil {
		t.Fatalf("CachedSessionIDRequired() error = nil, want missing-after-set error")
	}
}

func TestCachedSessionIDRequiredNonHomeModeUsesLocalMap(t *testing.T) {
	resetSessionIDCache()
	client := newFakeClaudeIDKVClient()
	useFakeClaudeIDKVClient(t, client, false, nil)

	first, errFirst := CachedSessionIDRequired(context.Background(), "api-key-1")
	if errFirst != nil {
		t.Fatalf("CachedSessionIDRequired() first error = %v", errFirst)
	}
	second, errSecond := CachedSessionIDRequired(context.Background(), "api-key-1")
	if errSecond != nil {
		t.Fatalf("CachedSessionIDRequired() second error = %v", errSecond)
	}
	if first != second {
		t.Fatalf("session id = %q then %q, want local cache reuse", first, second)
	}
	if client.getCount != 0 || client.setCount != 0 || client.expireCount != 0 {
		t.Fatalf("KV calls = get %d set %d expire %d, want all zero", client.getCount, client.setCount, client.expireCount)
	}
}

func TestCachedSessionIDRequiredHomeConcurrentInvalidRepairConverges(t *testing.T) {
	resetSessionIDCache()
	client := newFakeClaudeIDKVClient()
	key := claudeSessionIDKVKey("api-key-concurrent-repair")
	client.values[key] = []byte("invalid-session-id")
	useFakeClaudeIDKVClient(t, client, true, nil)

	const workers = 32
	results := make(chan string, workers)
	errorsFound := make(chan error, workers)
	var waitGroup sync.WaitGroup
	for range workers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			value, errValue := CachedSessionIDRequired(context.Background(), "api-key-concurrent-repair")
			if errValue != nil {
				errorsFound <- errValue
				return
			}
			results <- value
		}()
	}
	waitGroup.Wait()
	close(results)
	close(errorsFound)

	for errValue := range errorsFound {
		t.Errorf("CachedSessionIDRequired() error = %v", errValue)
	}
	var expected string
	for value := range results {
		if expected == "" {
			expected = value
		}
		if value != expected {
			t.Errorf("concurrent session ID = %q, want %q", value, expected)
		}
	}
	if !IsValidClaudeCodeUUID(expected) {
		t.Fatalf("concurrent replacement = %q, want canonical UUIDv4", expected)
	}
	client.mu.Lock()
	stored := string(client.values[key])
	client.mu.Unlock()
	if stored != expected {
		t.Fatalf("stored session ID = %q, want %q", stored, expected)
	}
}
