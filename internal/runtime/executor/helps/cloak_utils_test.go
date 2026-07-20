package helps

import (
	"errors"
	"strings"
	"testing"
)

func TestIsClaudeCodeClientUserAgentRequiresVersionedOfficialProfile(t *testing.T) {
	for _, userAgent := range []string{
		"claude-cli/2.1.215 (external, cli)",
		"claude-cli/2.1.215 (external, sdk-cli)",
		"claude-cli/2.2.0-beta.1 (external, vscode, extra)",
	} {
		if !IsClaudeCodeClientUserAgent(userAgent) {
			t.Fatalf("official User-Agent rejected: %q", userAgent)
		}
	}
	for _, userAgent := range []string{
		"claude-cli/",
		"claude-cli/2.1.215",
		"claude-cli/latest (external, cli)",
		"claude-cli/2.1 (external, cli)",
		"claude-cli/2.1.215 evil",
		"curl/8.0 claude-cli/2.1.215 (external, cli)",
	} {
		if IsClaudeCodeClientUserAgent(userAgent) {
			t.Fatalf("malformed User-Agent accepted: %q", userAgent)
		}
	}
}

type failingClaudeRandomReader struct{}

func (failingClaudeRandomReader) Read([]byte) (int, error) {
	return 0, errors.New("random source failed")
}

func TestParseClaudeCodeUserIDRequiresExactSchema(t *testing.T) {
	deviceID := strings.Repeat("a", 64)
	valid := `{"device_id":"` + deviceID + `","account_uuid":"","session_id":"` + testClaudeSessionA + `"}`
	parsed, errParse := ParseClaudeCodeUserID(" \n" + valid + "\t")
	if errParse != nil {
		t.Fatalf("ParseClaudeCodeUserID() error = %v", errParse)
	}
	if parsed.DeviceID != deviceID || parsed.AccountUUID != "" || parsed.SessionID != testClaudeSessionA {
		t.Fatalf("ParseClaudeCodeUserID() = %#v", parsed)
	}

	invalid := []string{
		`{"device_id":"` + deviceID + `","session_id":"` + testClaudeSessionA + `"}`,
		`{"device_id":"` + deviceID + `","account_uuid":"","session_id":"` + testClaudeSessionA + `","extra":"value"}`,
		`{"device_id":"` + deviceID + `","device_id":"` + deviceID + `","account_uuid":"","session_id":"` + testClaudeSessionA + `"}`,
		`{"device_id":"` + strings.ToUpper(deviceID) + `","account_uuid":"","session_id":"` + testClaudeSessionA + `"}`,
		`{"device_id":" ` + deviceID + `","account_uuid":"","session_id":"` + testClaudeSessionA + `"}`,
		`{"device_id":"` + deviceID + `","account_uuid":"","session_id":" ` + testClaudeSessionA + `"}`,
		`{"device_id":"` + deviceID + `","account_uuid":"","session_id":"11111111-1111-1111-8111-111111111111"}`,
		valid + ` true`,
		strings.Repeat(" ", maxClaudeCodeUserIDLength+1),
	}
	for _, userID := range invalid {
		if IsValidUserID(userID) {
			t.Fatalf("IsValidUserID(%q) = true, want false", userID)
		}
	}
}

func TestBuildClaudeCodeUserIDRequiredRejectsInvalidInputs(t *testing.T) {
	deviceID := strings.Repeat("b", 64)
	if _, errBuild := BuildClaudeCodeUserIDRequired("invalid", "", testClaudeSessionA); errBuild == nil {
		t.Fatal("BuildClaudeCodeUserIDRequired(invalid device) error = nil")
	}
	if _, errBuild := BuildClaudeCodeUserIDRequired(deviceID, "invalid", testClaudeSessionA); errBuild == nil {
		t.Fatal("BuildClaudeCodeUserIDRequired(invalid account) error = nil")
	}
	if _, errBuild := BuildClaudeCodeUserIDRequired(deviceID, "", "invalid"); errBuild == nil {
		t.Fatal("BuildClaudeCodeUserIDRequired(invalid session) error = nil")
	}
	userID, errBuild := BuildClaudeCodeUserIDRequired(deviceID, "", testClaudeSessionA)
	if errBuild != nil || !IsValidUserID(userID) {
		t.Fatalf("BuildClaudeCodeUserIDRequired() = %q, %v", userID, errBuild)
	}
}

func TestClaudeCodeRandomGenerationPropagatesReadErrors(t *testing.T) {
	if _, errDeviceID := generateClaudeCodeDeviceIDFromReader(failingClaudeRandomReader{}); errDeviceID == nil {
		t.Fatal("generateClaudeCodeDeviceIDFromReader() error = nil")
	}
	if _, errSessionID := generateClaudeCodeSessionIDFromReader(failingClaudeRandomReader{}); errSessionID == nil {
		t.Fatal("generateClaudeCodeSessionIDFromReader() error = nil")
	}
}

func TestGeneratedClaudeCodeIdentityIsCanonical(t *testing.T) {
	userID, errUserID := GenerateFakeUserIDRequired()
	if errUserID != nil {
		t.Fatalf("GenerateFakeUserIDRequired() error = %v", errUserID)
	}
	parsed, errParse := ParseClaudeCodeUserID(userID)
	if errParse != nil {
		t.Fatalf("ParseClaudeCodeUserID(generated) error = %v", errParse)
	}
	if !IsValidClaudeCodeDeviceID(parsed.DeviceID) || !IsValidClaudeCodeUUID(parsed.SessionID) {
		t.Fatalf("generated identity = %#v", parsed)
	}
}
