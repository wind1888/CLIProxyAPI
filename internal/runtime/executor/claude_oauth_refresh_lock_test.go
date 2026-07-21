package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestClaudeOAuthRefreshFileLockSerializesAndHonorsCancellation(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "claude-user.json")
	first, err := acquireClaudeOAuthRefreshFileLock(context.Background(), credentialPath)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	firstReleased := false
	t.Cleanup(func() {
		if !firstReleased {
			first.release()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err = acquireClaudeOAuthRefreshFileLock(ctx, credentialPath); err == nil {
		t.Fatal("second lock unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("lock cancellation took %v", elapsed)
	}

	first.release()
	firstReleased = true
	second, err := acquireClaudeOAuthRefreshFileLock(context.Background(), credentialPath)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	second.release()
}

func TestClaudeOAuthRefreshFileLockUsesExistingUnlockedFile(t *testing.T) {
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "claude-user.json")
	lockPath := credentialPath + ".oauth_refresh.lock"
	if err := os.WriteFile(lockPath, []byte("persistent lock inode"), 0600); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	lock, err := acquireClaudeOAuthRefreshFileLock(context.Background(), credentialPath)
	if err != nil {
		t.Fatalf("acquire existing unlocked lock file: %v", err)
	}
	lock.release()
}

func TestClaudeOAuthRefreshFileLockIsScopedPerCredential(t *testing.T) {
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "claude-user-a.json")
	first, err := acquireClaudeOAuthRefreshFileLock(context.Background(), credentialPath)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer first.release()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := acquireClaudeOAuthRefreshFileLock(ctx, filepath.Join(dir, "claude-user-b.json"))
	if err != nil {
		t.Fatalf("independent credential lock: %v", err)
	}
	second.release()
}

func TestClaudeOAuthRefreshFileLockReleaseKeepsReusableLockFile(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "claude-user.json")
	first, err := acquireClaudeOAuthRefreshFileLock(context.Background(), credentialPath)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	lockPath := first.lock.Path()
	first.release()
	if _, errStat := os.Stat(lockPath); errStat != nil {
		t.Fatalf("persistent lock file stat: %v", errStat)
	}
	second, err := acquireClaudeOAuthRefreshFileLock(context.Background(), credentialPath)
	if err != nil {
		t.Fatalf("reacquire released lock: %v", err)
	}
	second.release()
}

func TestHydrateClaudeOAuthStorageAcceptsOfficialCamelCaseMetadata(t *testing.T) {
	storage, metadata, err := readClaudeOAuthCredential(writeClaudeOAuthFixture(t, `{
		"access_token":"new-access","refresh_token":"new-refresh","expired":"2026-07-21T08:00:00Z",
		"scopes":["user:profile","user:inference"],
		"refreshTokenExpiresAt":1784600000000,
		"subscriptionType":"max","rateLimitTier":"default_claude_max_20x","clientId":"custom-client"
	}`))
	if err != nil {
		t.Fatalf("read credential: %v", err)
	}
	hydrateClaudeOAuthStorageAliases(storage, metadata)
	if storage.RefreshTokenExpiresAt != 1784600000000 || storage.SubscriptionType != "max" ||
		storage.RateLimitTier != "default_claude_max_20x" || storage.ClientID != "custom-client" {
		t.Fatalf("official metadata aliases not hydrated: %#v", storage)
	}
}

func TestClaudeOAuthRefreshRejectsUnreadableCredentialBeforeRotatingToken(t *testing.T) {
	dir := t.TempDir()
	name := "claude-user.json"
	path := filepath.Join(dir, name)
	want := []byte(`{"claudeAiOauth":`)
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatalf("write malformed credential: %v", err)
	}
	auth := &cliproxyauth.Auth{
		Provider: "claude",
		FileName: name,
		Metadata: map[string]any{
			"access_token":  "old-access",
			"refresh_token": "old-refresh",
		},
		Storage: &claudeauth.ClaudeTokenStorage{
			AccessToken:  "old-access",
			RefreshToken: "old-refresh",
		},
	}

	_, errRefresh := NewClaudeExecutor(&config.Config{AuthDir: dir}).Refresh(context.Background(), auth)
	if errRefresh == nil || !strings.Contains(errRefresh.Error(), "read Claude OAuth credential before refresh") {
		t.Fatalf("Refresh() error = %v, want pre-refresh credential read failure", errRefresh)
	}
	got, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read malformed credential after refresh: %v", errRead)
	}
	if string(got) != string(want) {
		t.Fatalf("malformed credential changed\nwant: %q\n got: %q", want, got)
	}
}

func writeClaudeOAuthFixture(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "claude-user.json")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write credential fixture: %v", err)
	}
	return path
}
