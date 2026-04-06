package helps

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/tlsspec"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// utlsRoundTripper implements http.RoundTripper using utls with Node.js TLS fingerprint
// to bypass Cloudflare's TLS fingerprinting on Anthropic domains.
type utlsRoundTripper struct {
	mu          sync.Mutex
	connections map[string]*http2.ClientConn
	pending     map[string]*sync.Cond
	dialer      proxy.Dialer
}

func newUtlsRoundTripper(proxyURL string) *utlsRoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("utls: failed to configure proxy dialer for %q: %v", proxyURL, errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}
	return &utlsRoundTripper{
		connections: make(map[string]*http2.ClientConn),
		pending:     make(map[string]*sync.Cond),
		dialer:      dialer,
	}
}

func (t *utlsRoundTripper) getOrCreateConnection(host, addr string) (*http2.ClientConn, error) {
	t.mu.Lock()

	// Fast path: reuse existing connection
	if h2Conn, ok := t.connections[host]; ok && h2Conn.CanTakeNewRequest() {
		t.mu.Unlock()
		return h2Conn, nil
	}

	// Another goroutine is already creating a connection for this host — wait for it
	if cond, ok := t.pending[host]; ok {
		cond.Wait() // atomically releases t.mu and suspends
		if h2Conn, ok := t.connections[host]; ok && h2Conn.CanTakeNewRequest() {
			t.mu.Unlock()
			return h2Conn, nil
		}
		// Connection still not available after wait — fall through to create one
	}

	// Mark this host as pending so other goroutines wait instead of racing
	cond := sync.NewCond(&t.mu)
	t.pending[host] = cond
	t.mu.Unlock()

	h2Conn, err := t.createConnection(host, addr)

	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.pending, host)
	cond.Broadcast()

	if err != nil {
		return nil, err
	}

	// If a stale connection exists, let it drain naturally — closing it would
	// disrupt any in-flight requests on shared HTTP/2 multiplexed streams.
	// Once removed from the map, no new requests will use it, and it will be
	// garbage collected after all existing streams complete.
	t.connections[host] = h2Conn
	return h2Conn, nil
}

func (t *utlsRoundTripper) createConnection(host, addr string) (*http2.ClientConn, error) {
	conn, err := t.dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{ServerName: host}
	// Use a custom ClientHelloSpec matching Node.js 20+ with OpenSSL 3.x,
	// which is what real Claude Code uses. This produces a JA3/JA4 fingerprint
	// consistent with Node.js rather than Chrome.
	tlsConn := tls.UClient(conn, tlsConfig, tls.HelloCustom)
	if err := tlsConn.ApplyPreset(tlsspec.NodeJS()); err != nil {
		conn.Close()
		return nil, err
	}

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	tr := &http2.Transport{}
	h2Conn, err := tr.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return h2Conn, nil
}

func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	hostname := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(hostname, port)

	h2Conn, err := t.getOrCreateConnection(hostname, addr)
	if err != nil {
		return nil, err
	}

	resp, err := h2Conn.RoundTrip(req)
	if err != nil {
		t.mu.Lock()
		if cached, ok := t.connections[hostname]; ok && cached == h2Conn {
			delete(t.connections, hostname)
		}
		t.mu.Unlock()
		return nil, err
	}

	return resp, nil
}

// anthropicHosts contains the hosts that should use utls TLS fingerprint.
// Includes known Anthropic API domains to ensure consistent TLS behavior
// even if Anthropic migrates to a different subdomain.
var anthropicHosts = map[string]struct{}{
	"api.anthropic.com":        {},
	"anthropic.com":            {},
	"claude.anthropic.com":     {},
	"api.claude.ai":            {},
	"console.anthropic.com":    {},
}

// fallbackRoundTripper uses utls for Anthropic HTTPS hosts and falls back to
// standard transport for all other requests (non-HTTPS or non-Anthropic hosts).
type fallbackRoundTripper struct {
	utls     *utlsRoundTripper
	fallback http.RoundTripper
}

func (f *fallbackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		if _, ok := anthropicHosts[strings.ToLower(req.URL.Hostname())]; ok {
			return f.utls.RoundTrip(req)
		}
	}
	return f.fallback.RoundTrip(req)
}

// utlsClientCache caches *http.Client instances by resolved proxy URL to enable
// HTTP/2 connection reuse across requests. Without caching, every request creates
// a fresh transport and pays the full TCP+TLS handshake cost (~50-200ms).
var utlsClientCache sync.Map // proxyURL -> *http.Client

// ResetUtlsClientCache clears the uTLS client cache.
// Call this when proxy configuration changes (e.g., config hot-reload).
func ResetUtlsClientCache() {
	utlsClientCache.Range(func(key, _ any) bool {
		utlsClientCache.Delete(key)
		return true
	})
}

// NewUtlsHTTPClient returns a cached HTTP client using utls with Node.js TLS fingerprint.
// Clients are cached by proxy URL to enable connection reuse across requests.
// Falls back to standard transport for non-HTTPS or non-Anthropic hosts.
func NewUtlsHTTPClient(cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	// Only cache clients without per-call timeout — timeout is a client-level
	// property that would affect all users of a shared client.
	if timeout <= 0 {
		if cached, ok := utlsClientCache.Load(proxyURL); ok {
			return cached.(*http.Client)
		}
	}

	utlsRT := newUtlsRoundTripper(proxyURL)

	var standardTransport http.RoundTripper = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	if proxyURL != "" {
		if transport := buildProxyTransport(proxyURL); transport != nil {
			standardTransport = transport
		}
	}

	client := &http.Client{
		Transport: &fallbackRoundTripper{
			utls:     utlsRT,
			fallback: standardTransport,
		},
	}

	if timeout > 0 {
		client.Timeout = timeout
		return client
	}

	actual, _ := utlsClientCache.LoadOrStore(proxyURL, client)
	return actual.(*http.Client)
}
