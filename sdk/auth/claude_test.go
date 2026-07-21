package auth

import (
	"errors"
	"testing"
	"time"
)

func TestClaudeAuthenticatorRefreshLeadMatchesClaudeCode(t *testing.T) {
	lead := NewClaudeAuthenticator().RefreshLead()
	if lead == nil || *lead != 5*time.Minute {
		t.Fatalf("RefreshLead() = %v, want 5m", lead)
	}
}

func TestUseClaudeManualOAuth(t *testing.T) {
	for _, test := range []struct {
		name             string
		noBrowser        bool
		browserAvailable bool
		want             bool
	}{
		{name: "no browser option", noBrowser: true, browserAvailable: true, want: true},
		{name: "browser unavailable", browserAvailable: false, want: true},
		{name: "automatic browser", browserAvailable: true, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := useClaudeManualOAuth(test.noBrowser, test.browserAvailable); got != test.want {
				t.Fatalf("useClaudeManualOAuth() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestParseClaudeManualOAuthInputUsesGeneratedState(t *testing.T) {
	result, description, err := parseClaudeManualOAuthInput("authorization-code#displayed-state", "generated-state")
	if err != nil {
		t.Fatalf("parseClaudeManualOAuthInput() error = %v", err)
	}
	if result == nil || result.Code != "authorization-code" || result.State != "generated-state" || result.Error != "" {
		t.Fatalf("result = %#v", result)
	}
	if description != "" {
		t.Fatalf("description = %q", description)
	}
}

func TestPromptClaudeManualOAuthIsSynchronous(t *testing.T) {
	wantErr := errors.New("prompt failed")
	called := false
	_, _, err := promptClaudeManualOAuth(func(string) (string, error) {
		called = true
		return "", wantErr
	}, "generated-state")
	if !called {
		t.Fatal("prompt was not called")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("promptClaudeManualOAuth() error = %v, want %v", err, wantErr)
	}
}

func TestPromptClaudeManualOAuthRequiresPrompt(t *testing.T) {
	if _, _, err := promptClaudeManualOAuth(nil, "generated-state"); err == nil {
		t.Fatal("promptClaudeManualOAuth(nil) returned nil error")
	}
}
