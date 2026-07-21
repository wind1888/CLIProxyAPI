// Package claude provides authentication and token management functionality
// for Anthropic's Claude AI services. It handles OAuth2 token storage, serialization,
// and retrieval for maintaining authenticated sessions with the Claude API.
package claude

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GeneratePKCECodes generates a PKCE code verifier and challenge pair
// following RFC 7636 specifications for OAuth 2.0 PKCE extension.
// This provides additional security for the OAuth flow by ensuring that
// only the client that initiated the request can exchange the authorization code.
//
// Returns:
//   - *PKCECodes: A struct containing the code verifier and challenge
//   - error: An error if the generation fails, nil otherwise
func GeneratePKCECodes() (*PKCECodes, error) {
	// Generate code verifier: 43-128 characters, URL-safe
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Generate code challenge using S256 method
	codeChallenge := generateCodeChallenge(codeVerifier)

	return &PKCECodes{
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
	}, nil
}

// generateCodeVerifier matches Claude Code's 43-character verifier.
func generateCodeVerifier() (string, error) {
	return generateClaudeOAuthRandomValue()
}

// GenerateOAuthState matches Claude Code's OAuth state generation: 32 random
// bytes encoded as unpadded base64url (43 characters).
func GenerateOAuthState() (string, error) {
	return generateClaudeOAuthRandomValue()
}

func generateClaudeOAuthRandomValue() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// generateCodeChallenge creates a SHA256 hash of the code verifier
// and encodes it using URL-safe base64 encoding without padding
func generateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}
