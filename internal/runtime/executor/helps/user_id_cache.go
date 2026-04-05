package helps

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
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

// userIDTTLNanos stores the TTL in nanoseconds for atomic access.
// Default 24h, increased from 1h to align with device profile lifecycle.
var userIDTTLNanos = int64(24 * time.Hour)

const (
	userIDCacheCleanupPeriod = 15 * time.Minute
)

// defaultUserIDTTL is the compiled-in default, used by ResetUserIDTTL.
const defaultUserIDTTL = 24 * time.Hour

// SetUserIDTTL overrides the user_id cache TTL. Use during config initialization.
func SetUserIDTTL(d time.Duration) {
	if d > 0 {
		atomic.StoreInt64(&userIDTTLNanos, int64(d))
	}
}

// ResetUserIDTTL restores the TTL to the compiled-in default (24h).
// Called on hot-reload when session-ttl is removed from config.
func ResetUserIDTTL() {
	atomic.StoreInt64(&userIDTTLNanos, int64(defaultUserIDTTL))
}

func getUserIDTTL() time.Duration {
	return time.Duration(atomic.LoadInt64(&userIDTTLNanos))
}

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
	if apiKey == "" {
		return generateFakeUserID()
	}

	userIDCacheCleanupOnce.Do(startUserIDCacheCleanup)

	ttl := getUserIDTTL()
	key := userIDCacheKey(apiKey)
	now := time.Now()

	userIDCacheMu.RLock()
	entry, ok := userIDCache[key]
	valid := ok && entry.value != "" && entry.expire.After(now) && isValidUserID(entry.value)
	userIDCacheMu.RUnlock()
	if valid {
		userIDCacheMu.Lock()
		entry = userIDCache[key]
		if entry.value != "" && entry.expire.After(now) && isValidUserID(entry.value) {
			entry.expire = now.Add(ttl)
			userIDCache[key] = entry
			userIDCacheMu.Unlock()
			return entry.value
		}
		userIDCacheMu.Unlock()
	}

	newID := generateFakeUserID()

	userIDCacheMu.Lock()
	entry, ok = userIDCache[key]
	if !ok || entry.value == "" || !entry.expire.After(now) || !isValidUserID(entry.value) {
		entry.value = newID
	}
	entry.expire = now.Add(ttl)
	userIDCache[key] = entry
	userIDCacheMu.Unlock()
	return entry.value
}
