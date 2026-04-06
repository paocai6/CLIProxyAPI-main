package helps

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

// proxyClientCache caches *http.Client instances by resolved proxy URL to enable
// connection reuse across requests for non-Claude providers.
var proxyClientCache sync.Map // proxyURL -> *http.Client

// ResetProxyClientCache clears the proxy client cache.
// Call this when proxy configuration changes (e.g., config hot-reload).
func ResetProxyClientCache() {
	proxyClientCache.Range(func(key, _ any) bool {
		proxyClientCache.Delete(key)
		return true
	})
}

// NewProxyAwareHTTPClient returns an HTTP client with proper proxy configuration.
// Clients are cached by proxy URL for connection reuse. Clients with non-zero
// timeout or context-provided RoundTrippers bypass the cache.
//
// Priority: auth.ProxyURL > cfg.ProxyURL > context RoundTripper
func NewProxyAwareHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	// Context RoundTripper is request-scoped, never cached
	if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
		return &http.Client{Transport: rt}
	}

	// Non-zero timeout clients are not cached (timeout is client-level, not per-request)
	if timeout > 0 {
		httpClient := &http.Client{Timeout: timeout}
		if proxyURL != "" {
			if transport := buildProxyTransport(proxyURL); transport != nil {
				httpClient.Transport = transport
			}
		}
		return httpClient
	}

	// Cache by resolved proxy URL (empty string = direct connection)
	if cached, ok := proxyClientCache.Load(proxyURL); ok {
		return cached.(*http.Client)
	}

	client := &http.Client{}
	if proxyURL != "" {
		if transport := buildProxyTransport(proxyURL); transport != nil {
			client.Transport = transport
		} else {
			log.Debugf("failed to setup proxy from URL: %s, using direct connection", proxyURL)
		}
	}
	actual, _ := proxyClientCache.LoadOrStore(proxyURL, client)
	return actual.(*http.Client)
}

// buildProxyTransport creates an HTTP transport configured for the given proxy URL.
// It supports SOCKS5, HTTP, and HTTPS proxy protocols.
//
// Parameters:
//   - proxyURL: The proxy URL string (e.g., "socks5://user:pass@host:port", "http://host:port")
//
// Returns:
//   - *http.Transport: A configured transport, or nil if the proxy URL is invalid
func buildProxyTransport(proxyURL string) *http.Transport {
	transport, _, errBuild := proxyutil.BuildHTTPTransport(proxyURL)
	if errBuild != nil {
		log.Errorf("%v", errBuild)
		return nil
	}
	return transport
}
