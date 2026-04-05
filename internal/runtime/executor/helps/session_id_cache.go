package helps

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
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

// sessionIDTTLNanos stores the TTL in nanoseconds for atomic access.
// Default 24h, increased from 1h to align with device profile lifecycle.
var sessionIDTTLNanos = int64(24 * time.Hour)

const (
	sessionIDCacheCleanupPeriod = 15 * time.Minute
)

// defaultSessionIDTTL is the compiled-in default, used by ResetSessionIDTTL.
const defaultSessionIDTTL = 24 * time.Hour

// SetSessionIDTTL overrides the session_id cache TTL. Use during config initialization.
func SetSessionIDTTL(d time.Duration) {
	if d > 0 {
		atomic.StoreInt64(&sessionIDTTLNanos, int64(d))
	}
}

// ResetSessionIDTTL restores the TTL to the compiled-in default (24h).
// Called on hot-reload when session-ttl is removed from config.
func ResetSessionIDTTL() {
	atomic.StoreInt64(&sessionIDTTLNanos, int64(defaultSessionIDTTL))
}

func getSessionIDTTL() time.Duration {
	return time.Duration(atomic.LoadInt64(&sessionIDTTLNanos))
}

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
	if apiKey == "" {
		return uuid.New().String()
	}

	sessionIDCacheCleanupOnce.Do(startSessionIDCacheCleanup)

	ttl := getSessionIDTTL()
	key := sessionIDCacheKey(apiKey)
	now := time.Now()

	sessionIDCacheMu.RLock()
	entry, ok := sessionIDCache[key]
	valid := ok && entry.value != "" && entry.expire.After(now)
	sessionIDCacheMu.RUnlock()
	if valid {
		sessionIDCacheMu.Lock()
		entry = sessionIDCache[key]
		if entry.value != "" && entry.expire.After(now) {
			entry.expire = now.Add(ttl)
			sessionIDCache[key] = entry
			sessionIDCacheMu.Unlock()
			return entry.value
		}
		sessionIDCacheMu.Unlock()
	}

	newID := uuid.New().String()

	sessionIDCacheMu.Lock()
	entry, ok = sessionIDCache[key]
	if !ok || entry.value == "" || !entry.expire.After(now) {
		entry.value = newID
	}
	entry.expire = now.Add(ttl)
	sessionIDCache[key] = entry
	sessionIDCacheMu.Unlock()
	return entry.value
}
