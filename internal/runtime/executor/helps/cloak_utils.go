package helps

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	claudeCodeDeviceIDPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	claudeCodeUserAgentPattern = regexp.MustCompile(`^claude-cli/[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)? \(external, [a-z][a-z0-9-]*(?:, [^()\r\n]+)*\)$`)
)

const maxClaudeCodeUserIDLength = 512
const maxClaudeCodeClientUserIDLength = 4096

// ClaudeCodeUserID is the canonical metadata.user_id payload emitted by Claude Code.
type ClaudeCodeUserID struct {
	DeviceID    string `json:"device_id"`
	AccountUUID string `json:"account_uuid"`
	SessionID   string `json:"session_id"`
}

func generateClaudeCodeDeviceIDRequired() (string, error) {
	return generateClaudeCodeDeviceIDFromReader(rand.Reader)
}

func generateClaudeCodeDeviceIDFromReader(random io.Reader) (string, error) {
	hexBytes := make([]byte, 32)
	if _, errRead := io.ReadFull(random, hexBytes); errRead != nil {
		return "", fmt.Errorf("generate Claude Code device ID: %w", errRead)
	}
	return hex.EncodeToString(hexBytes), nil
}

func generateClaudeCodeDeviceID() string {
	deviceID, _ := generateClaudeCodeDeviceIDRequired()
	return deviceID
}

func generateClaudeCodeSessionIDRequired() (string, error) {
	return generateClaudeCodeSessionIDFromReader(rand.Reader)
}

func generateClaudeCodeSessionIDFromReader(random io.Reader) (string, error) {
	sessionID, errUUID := uuid.NewRandomFromReader(random)
	if errUUID != nil {
		return "", fmt.Errorf("generate Claude Code session ID: %w", errUUID)
	}
	return sessionID.String(), nil
}

// generateFakeUserID generates Claude Code's metadata.user_id string format.
// Format: {"device_id":"<64 hex>","account_uuid":"","session_id":"<uuid>"}
func generateFakeUserID() string {
	userID, _ := generateFakeUserIDRequired()
	return userID
}

func generateFakeUserIDRequired() (string, error) {
	deviceID, errDeviceID := generateClaudeCodeDeviceIDRequired()
	if errDeviceID != nil {
		return "", errDeviceID
	}
	sessionID, errSessionID := generateClaudeCodeSessionIDRequired()
	if errSessionID != nil {
		return "", errSessionID
	}
	return buildClaudeCodeUserIDRequired(deviceID, "", sessionID)
}

// isValidUserID checks if a user ID matches Claude Code format.
func isValidUserID(userID string) bool {
	_, errParse := parseClaudeCodeUserID(userID)
	return errParse == nil
}

func isValidClaudeCodeDeviceID(deviceID string) bool {
	return claudeCodeDeviceIDPattern.MatchString(strings.TrimSpace(deviceID))
}

func isValidClaudeCodeUUID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 36 {
		return false
	}
	parsed, errParse := uuid.Parse(value)
	return errParse == nil &&
		parsed.Version() == 4 &&
		parsed.Variant() == uuid.RFC4122 &&
		parsed.String() == value
}

func buildClaudeCodeUserID(deviceID, accountUUID, sessionID string) string {
	deviceID = strings.TrimSpace(deviceID)
	if !isValidClaudeCodeDeviceID(deviceID) {
		generatedDeviceID, errDeviceID := generateClaudeCodeDeviceIDRequired()
		if errDeviceID != nil {
			return ""
		}
		deviceID = generatedDeviceID
	}
	accountUUID = strings.TrimSpace(accountUUID)
	if accountUUID != "" && !isValidClaudeCodeUUID(accountUUID) {
		accountUUID = ""
	}
	sessionID = strings.TrimSpace(sessionID)
	if !isValidClaudeCodeUUID(sessionID) {
		generatedSessionID, errSessionID := generateClaudeCodeSessionIDRequired()
		if errSessionID != nil {
			return ""
		}
		sessionID = generatedSessionID
	}
	return fmt.Sprintf(`{"device_id":"%s","account_uuid":"%s","session_id":"%s"}`, deviceID, accountUUID, sessionID)
}

func buildClaudeCodeUserIDRequired(deviceID, accountUUID, sessionID string) (string, error) {
	parsed := ClaudeCodeUserID{
		DeviceID:    strings.TrimSpace(deviceID),
		AccountUUID: strings.TrimSpace(accountUUID),
		SessionID:   strings.TrimSpace(sessionID),
	}
	if !isValidClaudeCodeDeviceID(parsed.DeviceID) {
		return "", errors.New("invalid Claude Code device ID")
	}
	if parsed.AccountUUID != "" && !isValidClaudeCodeUUID(parsed.AccountUUID) {
		return "", errors.New("invalid Claude Code account UUID")
	}
	if !isValidClaudeCodeUUID(parsed.SessionID) {
		return "", errors.New("invalid Claude Code session UUID")
	}
	encoded, errMarshal := json.Marshal(parsed)
	if errMarshal != nil {
		return "", fmt.Errorf("marshal Claude Code user ID: %w", errMarshal)
	}
	return string(encoded), nil
}

func parseClaudeCodeUserID(userID string) (ClaudeCodeUserID, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" || len(userID) > maxClaudeCodeUserIDLength {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code user ID length")
	}

	decoder := json.NewDecoder(strings.NewReader(userID))
	start, errStart := decoder.Token()
	if errStart != nil || start != json.Delim('{') {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code user ID object")
	}

	parsed := ClaudeCodeUserID{}
	seen := make(map[string]struct{}, 3)
	for decoder.More() {
		keyToken, errKey := decoder.Token()
		if errKey != nil {
			return ClaudeCodeUserID{}, fmt.Errorf("decode Claude Code user ID key: %w", errKey)
		}
		key, okKey := keyToken.(string)
		if !okKey {
			return ClaudeCodeUserID{}, errors.New("invalid Claude Code user ID key")
		}
		if _, duplicate := seen[key]; duplicate {
			return ClaudeCodeUserID{}, fmt.Errorf("duplicate Claude Code user ID field %q", key)
		}
		seen[key] = struct{}{}

		var value string
		if errValue := decoder.Decode(&value); errValue != nil {
			return ClaudeCodeUserID{}, fmt.Errorf("decode Claude Code user ID field %q: %w", key, errValue)
		}
		switch key {
		case "device_id":
			parsed.DeviceID = value
		case "account_uuid":
			parsed.AccountUUID = value
		case "session_id":
			parsed.SessionID = value
		default:
			return ClaudeCodeUserID{}, fmt.Errorf("unknown Claude Code user ID field %q", key)
		}
	}
	end, errEnd := decoder.Token()
	if errEnd != nil || end != json.Delim('}') {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code user ID object ending")
	}
	if _, errTrailing := decoder.Token(); !errors.Is(errTrailing, io.EOF) {
		return ClaudeCodeUserID{}, errors.New("trailing Claude Code user ID data")
	}
	if len(seen) != 3 {
		return ClaudeCodeUserID{}, errors.New("incomplete Claude Code user ID schema")
	}
	if parsed.DeviceID != strings.TrimSpace(parsed.DeviceID) ||
		parsed.AccountUUID != strings.TrimSpace(parsed.AccountUUID) ||
		parsed.SessionID != strings.TrimSpace(parsed.SessionID) {
		return ClaudeCodeUserID{}, errors.New("non-canonical whitespace in Claude Code user ID")
	}
	if !isValidClaudeCodeDeviceID(parsed.DeviceID) {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code device ID")
	}
	if parsed.AccountUUID != "" && !isValidClaudeCodeUUID(parsed.AccountUUID) {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code account UUID")
	}
	if !isValidClaudeCodeUUID(parsed.SessionID) {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code session UUID")
	}
	return parsed, nil
}

func GenerateFakeUserID() string {
	return generateFakeUserID()
}

func GenerateFakeUserIDRequired() (string, error) {
	return generateFakeUserIDRequired()
}

func GenerateClaudeCodeDeviceID() string {
	return generateClaudeCodeDeviceID()
}

func GenerateClaudeCodeDeviceIDRequired() (string, error) {
	return generateClaudeCodeDeviceIDRequired()
}

func GenerateClaudeCodeSessionIDRequired() (string, error) {
	return generateClaudeCodeSessionIDRequired()
}

func BuildClaudeCodeUserID(deviceID, accountUUID, sessionID string) string {
	return buildClaudeCodeUserID(deviceID, accountUUID, sessionID)
}

func BuildClaudeCodeUserIDRequired(deviceID, accountUUID, sessionID string) (string, error) {
	return buildClaudeCodeUserIDRequired(deviceID, accountUUID, sessionID)
}

func ParseClaudeCodeUserID(userID string) (ClaudeCodeUserID, error) {
	return parseClaudeCodeUserID(userID)
}

// ParseClaudeCodeClientUserID validates the three canonical identity fields
// while accepting metadata fields added by Claude Code itself, including
// parent_session_id for subagents.
func ParseClaudeCodeClientUserID(userID string) (ClaudeCodeUserID, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" || len(userID) > maxClaudeCodeClientUserIDLength {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code user ID length")
	}
	var fields map[string]json.RawMessage
	if errUnmarshal := json.Unmarshal([]byte(userID), &fields); errUnmarshal != nil || fields == nil {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code user ID JSON")
	}
	readString := func(name string, required bool) (string, error) {
		raw, exists := fields[name]
		if !exists {
			if required {
				return "", fmt.Errorf("missing Claude Code user ID field %s", name)
			}
			return "", nil
		}
		var value string
		if errDecode := json.Unmarshal(raw, &value); errDecode != nil {
			return "", fmt.Errorf("invalid Claude Code user ID field %s", name)
		}
		return strings.TrimSpace(value), nil
	}
	deviceID, errDeviceID := readString("device_id", true)
	if errDeviceID != nil || !isValidClaudeCodeDeviceID(deviceID) {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code device ID")
	}
	accountUUID, errAccountUUID := readString("account_uuid", true)
	if errAccountUUID != nil || (accountUUID != "" && !isValidClaudeCodeUUID(accountUUID)) {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code account UUID")
	}
	sessionID, errSessionID := readString("session_id", true)
	if errSessionID != nil || !isValidClaudeCodeUUID(sessionID) {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code session UUID")
	}
	parentSessionID, errParent := readString("parent_session_id", false)
	if errParent != nil || (parentSessionID != "" && !isValidClaudeCodeUUID(parentSessionID)) {
		return ClaudeCodeUserID{}, errors.New("invalid Claude Code parent session UUID")
	}
	return ClaudeCodeUserID{DeviceID: deviceID, AccountUUID: accountUUID, SessionID: sessionID}, nil
}

func IsValidClaudeCodeDeviceID(deviceID string) bool {
	return isValidClaudeCodeDeviceID(deviceID)
}

func IsValidUserID(userID string) bool {
	return isValidUserID(userID)
}

func IsValidClaudeCodeUUID(value string) bool {
	return isValidClaudeCodeUUID(value)
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
		return !IsClaudeCodeClientUserAgent(userAgent)
	}
}

// isClaudeCodeClient checks if the User-Agent indicates a Claude Code client.
func isClaudeCodeClient(userAgent string) bool {
	return IsClaudeCodeClientUserAgent(userAgent)
}

// IsClaudeCodeClientUserAgent reports whether userAgent uses Claude Code's
// versioned claude-cli product token.
func IsClaudeCodeClientUserAgent(userAgent string) bool {
	return claudeCodeUserAgentPattern.MatchString(strings.TrimSpace(userAgent))
}
