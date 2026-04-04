package gemini

import (
	"fmt"
	"os"
	"strings"
)

const (
	OAuthClientIDEnv     = "GEMINI_OAUTH_CLIENT_ID"
	OAuthClientSecretEnv = "GEMINI_OAUTH_CLIENT_SECRET"
)

// OAuthClientID returns the Gemini OAuth client ID from the environment.
func OAuthClientID() string {
	return strings.TrimSpace(os.Getenv(OAuthClientIDEnv))
}

// OAuthClientSecret returns the Gemini OAuth client secret from the environment.
func OAuthClientSecret() string {
	return strings.TrimSpace(os.Getenv(OAuthClientSecretEnv))
}

// OAuthClientCredentials returns the Gemini OAuth client credentials.
func OAuthClientCredentials() (string, string, error) {
	clientID := OAuthClientID()
	clientSecret := OAuthClientSecret()
	if clientID == "" || clientSecret == "" {
		return "", "", fmt.Errorf("gemini oauth credentials not configured: set %s and %s", OAuthClientIDEnv, OAuthClientSecretEnv)
	}
	return clientID, clientSecret, nil
}
