package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSessionCacheExpiredGetDoesNotDeleteConcurrentSet(t *testing.T) {
	cache := NewSessionCache(time.Minute)
	defer cache.Stop()

	const sessionID = "session"
	expired := sessionEntry{
		authID:    "old-auth",
		expiresAt: time.Now().Add(-time.Minute),
	}
	cache.mu.Lock()
	cache.entries[sessionID] = expired
	cache.mu.Unlock()

	// Reproduce the stale snapshot held by Get immediately before a concurrent
	// Set replaces it. The stale cleanup must leave the replacement intact.
	cache.Set(sessionID, "new-auth")
	cache.deleteExpiredIfUnchanged(sessionID, expired)

	got, ok := cache.Get(sessionID)
	if !ok || got != "new-auth" {
		t.Fatalf("Get() after stale cleanup = %q, %v, want new-auth, true", got, ok)
	}
}

func TestSessionCacheConcurrentGetSet(t *testing.T) {
	cache := NewSessionCache(time.Minute)
	defer cache.Stop()

	const (
		workers    = 16
		iterations = 200
	)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				cache.Set("session", fmt.Sprintf("auth-%d", worker))
				cache.Get("session")
				cache.GetAndRefresh("session")
			}
		}()
	}
	close(start)
	wg.Wait()

	cache.Set("session", "final-auth")
	got, ok := cache.Get("session")
	if !ok || got != "final-auth" {
		t.Fatalf("Get() after concurrent access = %q, %v, want final-auth, true", got, ok)
	}
}

func TestSessionCacheConcurrentStop(t *testing.T) {
	cache := NewSessionCache(time.Nanosecond)
	cache.Set("session", "auth")

	const callers = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			cache.Stop()
			cache.Stop()
		}()
	}
	close(start)
	wg.Wait()

	select {
	case <-cache.doneCh:
	default:
		t.Fatal("Stop() returned before the cleanup goroutine exited")
	}
}
