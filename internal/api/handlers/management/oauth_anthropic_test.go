package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestRequestAnthropicTokenAlwaysUsesHostedManualRedirect(t *testing.T) {
	for _, test := range []struct {
		name  string
		query string
	}{
		{name: "CLI management client"},
		{name: "remote Web UI", query: "?is_webui=true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := NewHandlerWithoutConfigFilePath(&config.Config{
				AuthDir: filepath.Join(t.TempDir(), "auths"),
			}, nil)
			router := gin.New()
			router.GET("/anthropic-auth-url", handler.RequestAnthropicToken)

			req := httptest.NewRequest(http.MethodGet, "/anthropic-auth-url"+test.query, nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}

			var payload struct {
				URL       string `json:"url"`
				ManualURL string `json:"manual_url"`
				State     string `json:"state"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if payload.State == "" {
				t.Fatal("response state is empty")
			}
			defer CancelOAuthSession(payload.State)
			if payload.URL != payload.ManualURL {
				t.Fatalf("url = %q, manual_url = %q", payload.URL, payload.ManualURL)
			}
			parsed, err := url.Parse(payload.URL)
			if err != nil {
				t.Fatalf("parse authorization URL: %v", err)
			}
			if got := parsed.Query().Get("redirect_uri"); got != claude.RedirectURI {
				t.Fatalf("redirect_uri = %q, want %q", got, claude.RedirectURI)
			}
		})
	}
}
