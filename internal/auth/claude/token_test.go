package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSaveTokenToFileAtomicallyReplacesWithSecureAuthoritativeData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	if err := os.WriteFile(path, []byte(`{"access_token":"old"}`), 0644); err != nil {
		t.Fatalf("write old credential: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod old credential: %v", err)
	}

	storage := &ClaudeTokenStorage{
		IDToken:               "new-id",
		AccessToken:           "new-access",
		RefreshToken:          "new-refresh",
		LastRefresh:           "2026-07-21T00:00:00Z",
		Email:                 "user@example.com",
		AccountUUID:           "account-uuid",
		OrganizationUUID:      "organization-uuid",
		Scopes:                []string{"user:profile", "user:inference"},
		RefreshTokenExpiresAt: 1784600000000,
		SubscriptionType:      "max",
		RateLimitTier:         "default_claude_max_20x",
		ClientID:              "custom-client",
		Expire:                "2026-07-21T01:00:00Z",
		Metadata: map[string]any{
			"access_token":  "stale-access",
			"refresh_token": "stale-refresh",
			"scopes":        []string{"stale:scope"},
			"custom":        "preserved",
		},
	}
	if err := storage.SaveTokenToFile(path); err != nil {
		t.Fatalf("SaveTokenToFile() error = %v", err)
	}

	info, errStat := os.Stat(path)
	if errStat != nil {
		t.Fatalf("stat credential: %v", errStat)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("credential permissions = %04o, want 0600", info.Mode().Perm())
	}

	payload, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read credential: %v", errRead)
	}
	var got map[string]any
	if errUnmarshal := json.Unmarshal(payload, &got); errUnmarshal != nil {
		t.Fatalf("credential is not valid JSON: %v", errUnmarshal)
	}
	for key, want := range map[string]string{
		"id_token":          "new-id",
		"access_token":      "new-access",
		"refresh_token":     "new-refresh",
		"last_refresh":      "2026-07-21T00:00:00Z",
		"email":             "user@example.com",
		"account_uuid":      "account-uuid",
		"organization_uuid": "organization-uuid",
		"subscription_type": "max",
		"rate_limit_tier":   "default_claude_max_20x",
		"client_id":         "custom-client",
		"expired":           "2026-07-21T01:00:00Z",
		"type":              "claude",
		"custom":            "preserved",
	} {
		if gotValue, _ := got[key].(string); gotValue != want {
			t.Errorf("credential[%q] = %q, want %q", key, gotValue, want)
		}
	}
	scopes, ok := got["scopes"].([]any)
	if !ok || len(scopes) != 2 || scopes[0] != "user:profile" || scopes[1] != "user:inference" {
		t.Fatalf("credential scopes = %#v, want authoritative typed scopes", got["scopes"])
	}
	if gotExpiry, ok := got["refresh_token_expires_at"].(float64); !ok || int64(gotExpiry) != 1784600000000 {
		t.Fatalf("credential refresh_token_expires_at = %#v", got["refresh_token_expires_at"])
	}
	assertNoClaudeTokenTempFiles(t, dir)
}

func TestSaveTokenToFileSerializationFailurePreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	want := []byte("existing credential remains byte-for-byte\n")
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatalf("write old credential: %v", err)
	}

	storage := &ClaudeTokenStorage{
		AccessToken: "new-access",
		Metadata: map[string]any{
			"unsupported": make(chan int),
		},
	}
	if err := storage.SaveTokenToFile(path); err == nil {
		t.Fatal("SaveTokenToFile() error = nil, want serialization error")
	}

	got, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read old credential: %v", errRead)
	}
	if string(got) != string(want) {
		t.Fatalf("old credential changed after failed save\ngot:  %q\nwant: %q", got, want)
	}
	assertNoClaudeTokenTempFiles(t, dir)
}

func TestDecodeAndSaveOfficialClaudeCodeCredentialEnvelope(t *testing.T) {
	raw := []byte(`{
		"installMethod":"native",
		"claudeAiOauth":{
			"accessToken":"old-access","refreshToken":"old-refresh",
			"expiresAt":1784600000123,"refreshTokenExpiresAt":1787200000456,
			"scopes":["user:profile","user:inference"],
			"subscriptionType":"max","rateLimitTier":"default_claude_max_20x"
		}
	}`)
	storage, metadata, official, errDecode := DecodeTokenStorage(raw)
	if errDecode != nil {
		t.Fatalf("DecodeTokenStorage() error = %v", errDecode)
	}
	if !official {
		t.Fatal("DecodeTokenStorage() official = false, want true")
	}
	if storage.AccessToken != "old-access" || storage.RefreshToken != "old-refresh" {
		t.Fatalf("decoded tokens = %q/%q", storage.AccessToken, storage.RefreshToken)
	}
	if got := metadata["access_token"]; got != "old-access" {
		t.Fatalf("flattened access_token = %#v", got)
	}
	if got, errParse := time.Parse(time.RFC3339, storage.Expire); errParse != nil || got.UnixMilli() != 1784600000123 {
		t.Fatalf("decoded expiry = %q (%v)", storage.Expire, errParse)
	}

	storage.AccessToken = "new-access"
	storage.RefreshToken = "new-refresh"
	storage.Expire = time.UnixMilli(1784603600789).UTC().Format(time.RFC3339Nano)
	storage.Scopes = []string{"user:profile", "user:inference", "user:sessions:claude_code"}
	storage.ClientID = "custom-client"
	path := filepath.Join(t.TempDir(), ".credentials.json")
	if errSave := storage.SaveOfficialTokenToFile(path, metadata); errSave != nil {
		t.Fatalf("SaveOfficialTokenToFile() error = %v", errSave)
	}
	written, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read saved official credential: %v", errRead)
	}
	var envelope map[string]any
	if errUnmarshal := json.Unmarshal(written, &envelope); errUnmarshal != nil {
		t.Fatalf("saved credential JSON: %v", errUnmarshal)
	}
	if envelope["installMethod"] != "native" {
		t.Fatalf("unrelated top-level field was not preserved: %#v", envelope)
	}
	nested, _ := envelope["claudeAiOauth"].(map[string]any)
	if nested["accessToken"] != "new-access" || nested["refreshToken"] != "new-refresh" {
		t.Fatalf("saved official tokens = %#v", nested)
	}
	if got := int64(nested["expiresAt"].(float64)); got != 1784603600789 {
		t.Fatalf("saved expiresAt = %d", got)
	}
	if _, exists := envelope["access_token"]; exists {
		t.Fatalf("flat CPA fields leaked into official envelope: %#v", envelope)
	}
}

func assertNoClaudeTokenTempFiles(t *testing.T, dir string) {
	t.Helper()
	matches, errGlob := filepath.Glob(filepath.Join(dir, ".claude.json.tmp-*"))
	if errGlob != nil {
		t.Fatalf("glob token temp files: %v", errGlob)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary token files were not cleaned up: %v", matches)
	}
}
