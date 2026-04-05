package auth

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// authPacer enforces per-auth request pacing to simulate real CLI usage patterns.
// It limits concurrency (max in-flight requests per auth) and enforces a minimum
// interval between consecutive requests to the same auth.
//
// Design rationale:
// A real Claude Code CLI session is serial — one request at a time, with human
// think-time (2-10s) between requests. A proxy serving 2000 users through 100
// accounts creates a pattern where one account receives many concurrent requests,
// which is a strong detection signal. The pacer makes each account's traffic look
// like a single active user.
type authPacer struct {
	mu    sync.Mutex
	slots map[string]*authSlot

	// Configurable parameters (atomic for hot-reload safety).
	maxConcurrency int32 // max in-flight per auth (default 1)
	minIntervalNs  int64 // min nanoseconds between requests to same auth
	jitterNs       int64 // random jitter added to interval
	enabled        int32 // 1 = enabled, 0 = disabled
}

// authSlot tracks per-auth pacing state.
type authSlot struct {
	mu          sync.Mutex
	sem         chan struct{} // concurrency semaphore
	lastRelease time.Time    // when the last request finished
}

func newAuthPacer() *authPacer {
	return &authPacer{
		slots:          make(map[string]*authSlot),
		maxConcurrency: 1,
		minIntervalNs:  int64(2 * time.Second),
		jitterNs:       int64(3 * time.Second),
		enabled:        0, // disabled by default, opt-in
	}
}

// Configure updates pacer parameters. Safe for concurrent use.
// NOTE: maxConcurrency changes only apply to newly created slots. Existing slots
// keep their old semaphore capacity until the process restarts or the slot is
// recreated. This avoids goroutine leaks from replacing channels mid-flight.
func (p *authPacer) Configure(maxConcurrency int, minInterval, jitter time.Duration, enabled bool) {
	if maxConcurrency < 1 {
		maxConcurrency = 1
	}
	atomic.StoreInt32(&p.maxConcurrency, int32(maxConcurrency))
	atomic.StoreInt64(&p.minIntervalNs, int64(minInterval))
	atomic.StoreInt64(&p.jitterNs, int64(jitter))
	if enabled {
		atomic.StoreInt32(&p.enabled, 1)
	} else {
		atomic.StoreInt32(&p.enabled, 0)
	}
	// Semaphore channels are NOT replaced for existing slots to avoid leaking
	// goroutines that are blocked on or hold references to the old channel.
	// New slots created after this call will use the updated maxConcurrency.
}

// IsEnabled returns whether pacing is active.
func (p *authPacer) IsEnabled() bool {
	return atomic.LoadInt32(&p.enabled) == 1
}

// getSlot returns or creates the pacing slot for an auth ID.
func (p *authPacer) getSlot(authID string) *authSlot {
	p.mu.Lock()
	defer p.mu.Unlock()
	slot, ok := p.slots[authID]
	if !ok {
		maxConc := int(atomic.LoadInt32(&p.maxConcurrency))
		slot = &authSlot{
			sem: make(chan struct{}, maxConc),
		}
		p.slots[authID] = slot
	}
	return slot
}

// RemoveSlot cleans up the pacing slot for a removed auth.
// Call this when an account is deregistered to prevent unbounded map growth.
func (p *authPacer) RemoveSlot(authID string) {
	p.mu.Lock()
	delete(p.slots, authID)
	p.mu.Unlock()
}

// Acquire blocks until the auth slot is available or ctx is cancelled.
// Returns a release function that MUST be called exactly once when the request
// completes (including when the response stream finishes).
// If pacing is disabled or authID is empty, returns immediately with a no-op release.
func (p *authPacer) Acquire(ctx context.Context, authID string) (release func(), err error) {
	noop := func() {}
	if !p.IsEnabled() {
		return noop, nil
	}
	// Skip pacing for empty auth IDs to avoid coalescing unrelated accounts.
	if authID == "" {
		return noop, nil
	}

	slot := p.getSlot(authID)

	// Wait for concurrency slot.
	select {
	case slot.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Enforce minimum interval since last release on this auth.
	minInterval := time.Duration(atomic.LoadInt64(&p.minIntervalNs))
	jitter := time.Duration(atomic.LoadInt64(&p.jitterNs))

	slot.mu.Lock()
	elapsed := time.Since(slot.lastRelease)
	slot.mu.Unlock()

	target := minInterval
	if jitter > 0 {
		target += time.Duration(rand.Int63n(int64(jitter)))
	}

	if elapsed < target && !slot.lastRelease.IsZero() {
		wait := target - elapsed
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			// Release concurrency slot on cancel.
			<-slot.sem
			return nil, ctx.Err()
		}
	}

	// Guard against double-release with sync.Once.
	var once sync.Once
	release = func() {
		once.Do(func() {
			slot.mu.Lock()
			slot.lastRelease = time.Now()
			slot.mu.Unlock()
			<-slot.sem
		})
	}
	return release, nil
}

// AcquirePostRetry adds a random delay after a 429 retry, simulating a real
// user who would pause and switch tasks after hitting a rate limit.
// This prevents the mechanical pattern of instant credential rotation.
func (p *authPacer) AcquirePostRetry(ctx context.Context) error {
	if !p.IsEnabled() {
		return nil
	}
	// Random delay 3-15 seconds to break mechanical rotation pattern.
	delay := 3*time.Second + time.Duration(rand.Int63n(int64(12*time.Second)))
	timer := time.NewTimer(delay)
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	}
}
