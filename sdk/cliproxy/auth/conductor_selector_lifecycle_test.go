package auth

import (
	"sync"
	"testing"
	"time"
)

func assertSessionSelectorRunning(t *testing.T, selector *SessionAffinitySelector) {
	t.Helper()
	cache := selector.currentCache()
	if cache == nil {
		t.Fatal("session selector has no active cache")
	}
	select {
	case <-cache.doneCh:
		t.Fatal("session selector cleanup goroutine is stopped")
	default:
	}
}

func assertSessionSelectorStopped(t *testing.T, selector *SessionAffinitySelector) {
	t.Helper()
	if cache := selector.currentCache(); cache != nil {
		t.Fatal("session selector still has an active cache")
	}
}

type blockingRestartableSessionSelector struct {
	*SessionAffinitySelector
	stopEntered chan struct{}
	stopRelease chan struct{}
	stopOnce    sync.Once
}

func newBlockingRestartableSessionSelector() *blockingRestartableSessionSelector {
	return &blockingRestartableSessionSelector{
		SessionAffinitySelector: NewSessionAffinitySelector(&RoundRobinSelector{}),
		stopEntered:             make(chan struct{}),
		stopRelease:             make(chan struct{}),
	}
}

func (s *blockingRestartableSessionSelector) Stop() {
	s.stopOnce.Do(func() { close(s.stopEntered) })
	<-s.stopRelease
	s.SessionAffinitySelector.Stop()
}

func TestManagerSetSelectorStopsOnlyReplacedSelector(t *testing.T) {
	first := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Minute,
	})
	manager := NewManager(nil, first, nil)

	// Reinstalling the same resource-owning selector must not stop the active
	// instance.
	manager.SetSelector(first)
	assertSessionSelectorRunning(t, first)

	second := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &FillFirstSelector{},
		TTL:      time.Minute,
	})
	manager.SetSelector(second)
	assertSessionSelectorStopped(t, first)
	assertSessionSelectorRunning(t, second)

	manager.SetSelector(&RoundRobinSelector{})
	assertSessionSelectorStopped(t, second)
}

func TestManagerSetSelectorRestartsRetiredSessionSelector(t *testing.T) {
	first := NewSessionAffinitySelector(&RoundRobinSelector{})
	manager := NewManager(nil, first, nil)
	oldCache := first.currentCache()

	second := NewSessionAffinitySelector(&FillFirstSelector{})
	manager.SetSelector(second)
	assertSessionSelectorStopped(t, first)
	select {
	case <-oldCache.doneCh:
	default:
		t.Fatal("retired selector's old cleanup goroutine is still running")
	}

	manager.SetSelector(first)
	assertSessionSelectorRunning(t, first)
	if restartedCache := first.currentCache(); restartedCache == oldCache {
		t.Fatal("restarted selector reused its stopped cache")
	}
	assertSessionSelectorStopped(t, second)

	manager.SetSelector(&RoundRobinSelector{})
	assertSessionSelectorStopped(t, first)
}

func TestManagerSetSelectorConcurrentABAReactivatesCurrentSelector(t *testing.T) {
	first := newBlockingRestartableSessionSelector()
	manager := NewManager(nil, first, nil)
	initialCache := first.currentCache()
	second := NewSessionAffinitySelector(&FillFirstSelector{})

	firstTransitionDone := make(chan struct{})
	go func() {
		manager.SetSelector(second)
		close(firstTransitionDone)
	}()

	select {
	case <-first.stopEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("A -> B transition did not enter A.Stop")
	}

	secondTransitionDone := make(chan struct{})
	go func() {
		manager.SetSelector(first)
		close(secondTransitionDone)
	}()

	// The B -> A transition must wait until the A -> B retirement has fully
	// stopped A. Otherwise the earlier Stop can target the newly current A.
	select {
	case <-secondTransitionDone:
		t.Fatal("B -> A transition completed while A retirement was blocked")
	case <-time.After(25 * time.Millisecond):
	}

	close(first.stopRelease)
	select {
	case <-firstTransitionDone:
	case <-time.After(5 * time.Second):
		t.Fatal("A -> B transition did not complete")
	}
	select {
	case <-secondTransitionDone:
	case <-time.After(5 * time.Second):
		t.Fatal("B -> A transition did not complete")
	}

	manager.mu.RLock()
	current := manager.selector
	manager.mu.RUnlock()
	if !sameSelectorInstance(current, first) {
		t.Fatalf("current selector = %T, want reactivated A", current)
	}
	assertSessionSelectorRunning(t, first.SessionAffinitySelector)
	if restartedCache := first.currentCache(); restartedCache == initialCache {
		t.Fatal("ABA reactivation reused A's stopped cache")
	}
	select {
	case <-initialCache.doneCh:
	default:
		t.Fatal("A's retired cleanup goroutine is still running")
	}
	assertSessionSelectorStopped(t, second)

	manager.SetSelector(&RoundRobinSelector{})
	assertSessionSelectorStopped(t, first.SessionAffinitySelector)
}

func TestManagerSelectorConcurrentReplacementLifecycle(t *testing.T) {
	initial := NewSessionAffinitySelector(&RoundRobinSelector{})
	manager := NewManager(nil, initial, nil)

	const replacements = 48
	selectors := make([]*SessionAffinitySelector, 0, replacements+1)
	selectors = append(selectors, initial)
	for i := 0; i < replacements; i++ {
		selectors = append(selectors, NewSessionAffinitySelector(&RoundRobinSelector{}))
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 1; i < len(selectors); i++ {
		selector := selectors[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			manager.SetSelector(selector)
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 200; j++ {
				manager.useSchedulerFastPath()
				manager.invalidateSessionAffinity("auth-id")
				manager.StopAutoRefresh()
			}
		}()
	}
	close(start)
	wg.Wait()

	// Replacing the last active selector with a stateless selector ensures every
	// SessionAffinitySelector created by the test has left no cleanup goroutine.
	manager.SetSelector(&FillFirstSelector{})
	for _, selector := range selectors {
		assertSessionSelectorStopped(t, selector)
	}
	if !manager.useSchedulerFastPath() {
		t.Fatal("final built-in selector did not enable the scheduler fast path")
	}
	if manager.scheduler.strategy != schedulerStrategyFillFirst {
		t.Fatalf("scheduler strategy = %v, want %v", manager.scheduler.strategy, schedulerStrategyFillFirst)
	}
}
