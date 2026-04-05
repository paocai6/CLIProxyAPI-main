package helps

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// userIDPattern matches Claude Code format: user_[64-hex]_account_[uuid]_session_[uuid]
var userIDPattern = regexp.MustCompile(`^user_[a-fA-F0-9]{64}_account_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_session_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// generateFakeUserID generates a fake user ID in Claude Code format.
// Format: user_[64-hex-chars]_account_[UUID-v4]_session_[UUID-v4]
// When accountUUID is provided, it is used instead of a random UUID to match
// the real OAuth account, preventing server-side cross-validation failures.
func generateFakeUserID(accountUUID ...string) string {
	hexBytes := make([]byte, 32)
	_, _ = rand.Read(hexBytes)
	hexPart := hex.EncodeToString(hexBytes)
	acctUUID := uuid.New().String()
	if len(accountUUID) > 0 && accountUUID[0] != "" {
		acctUUID = accountUUID[0]
	}
	sessionUUID := uuid.New().String()
	return "user_" + hexPart + "_account_" + acctUUID + "_session_" + sessionUUID
}

// GenerateFakeUserIDWithAccount generates a user ID using the real account UUID.
func GenerateFakeUserIDWithAccount(accountUUID string) string {
	return generateFakeUserID(accountUUID)
}

// isValidUserID checks if a user ID matches Claude Code format.
func isValidUserID(userID string) bool {
	return userIDPattern.MatchString(userID)
}

func GenerateFakeUserID() string {
	return generateFakeUserID()
}

func IsValidUserID(userID string) bool {
	return isValidUserID(userID)
}

// ShouldCloak determines if request should be cloaked based on config and client User-Agent.
// Returns true if cloaking should be applied.
func ShouldCloak(cloakMode string, userAgent string) bool {
	switch strings.ToLower(cloakMode) {
	case "always":
		return true
	case "never":
		return false
	default: // "auto" or empty
		// If client is Claude Code, don't cloak
		return !strings.HasPrefix(userAgent, "claude-cli")
	}
}

// ShouldCloakByAuth determines cloaking based on auth type instead of client UA.
// This is more reliable than UA-based detection: OAuth tokens indicate a real
// Claude Code subscription (don't cloak), API keys indicate third-party use (cloak).
func ShouldCloakByAuth(cloakMode, apiKey string) bool {
	switch strings.ToLower(cloakMode) {
	case "always":
		return true
	case "never":
		return false
	default: // "auto"
		// OAuth tokens come from real Claude Code subscriptions — don't cloak
		return !strings.HasPrefix(apiKey, "sk-ant-oat")
	}
}

// isClaudeCodeClient checks if the User-Agent indicates a Claude Code client.
func isClaudeCodeClient(userAgent string) bool {
	return strings.HasPrefix(userAgent, "claude-cli")
}
