package helps

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	claudeCodeDeviceIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	claudeCodeUUIDPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type claudeCodeUserID struct {
	DeviceID    string `json:"device_id"`
	AccountUUID string `json:"account_uuid"`
	SessionID   string `json:"session_id"`
}

func generateClaudeCodeDeviceID() string {
	hexBytes := make([]byte, 32)
	_, _ = rand.Read(hexBytes)
	return hex.EncodeToString(hexBytes)
}

// generateFakeUserID generates Claude Code's metadata.user_id string format.
// Format: {"device_id":"<64 hex>","account_uuid":"","session_id":"<uuid>"}
func generateFakeUserID() string {
	return buildClaudeCodeUserID(generateClaudeCodeDeviceID(), "", uuid.New().String())
}

// isValidUserID checks if a user ID matches Claude Code format.
func isValidUserID(userID string) bool {
	var parsed claudeCodeUserID
	if err := json.Unmarshal([]byte(strings.TrimSpace(userID)), &parsed); err != nil {
		return false
	}
	return isValidClaudeCodeDeviceID(parsed.DeviceID) &&
		(parsed.AccountUUID == "" || isValidClaudeCodeUUID(parsed.AccountUUID)) &&
		isValidClaudeCodeUUID(parsed.SessionID)
}

func isValidClaudeCodeDeviceID(deviceID string) bool {
	return claudeCodeDeviceIDPattern.MatchString(strings.TrimSpace(deviceID))
}

func isValidClaudeCodeUUID(value string) bool {
	return claudeCodeUUIDPattern.MatchString(strings.TrimSpace(value))
}

func buildClaudeCodeUserID(deviceID, accountUUID, sessionID string) string {
	deviceID = strings.TrimSpace(deviceID)
	if !isValidClaudeCodeDeviceID(deviceID) {
		deviceID = generateClaudeCodeDeviceID()
	}
	accountUUID = strings.TrimSpace(accountUUID)
	if accountUUID != "" && !isValidClaudeCodeUUID(accountUUID) {
		accountUUID = ""
	}
	sessionID = strings.TrimSpace(sessionID)
	if !isValidClaudeCodeUUID(sessionID) {
		sessionID = uuid.New().String()
	}
	return fmt.Sprintf(`{"device_id":"%s","account_uuid":"%s","session_id":"%s"}`, deviceID, accountUUID, sessionID)
}

func GenerateFakeUserID() string {
	return generateFakeUserID()
}

func GenerateClaudeCodeDeviceID() string {
	return generateClaudeCodeDeviceID()
}

func BuildClaudeCodeUserID(deviceID, accountUUID, sessionID string) string {
	return buildClaudeCodeUserID(deviceID, accountUUID, sessionID)
}

func IsValidClaudeCodeDeviceID(deviceID string) bool {
	return isValidClaudeCodeDeviceID(deviceID)
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

// isClaudeCodeClient checks if the User-Agent indicates a Claude Code client.
func isClaudeCodeClient(userAgent string) bool {
	return strings.HasPrefix(userAgent, "claude-cli")
}
