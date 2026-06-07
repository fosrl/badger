package badger_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	badger "github.com/fosrl/badger"
)

// newTestHandler builds a Badger handler with the given config, failing the test
// if construction returns an unexpected error.
func newTestHandler(t *testing.T, cfg *badger.Config, next http.Handler) http.Handler {
	t.Helper()
	h, err := badger.New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}
	return h
}

func TestCreateConfig(t *testing.T) {
	if badger.CreateConfig() == nil {
		t.Fatal("CreateConfig() returned nil")
	}
}

func TestNewRequiresFieldsWhenForwardAuthEnabled(t *testing.T) {
	cases := map[string]*badger.Config{
		"missing apiBaseURL": {
			UserSessionCookieName:       "p_session_token",
			ResourceSessionRequestParam: "p_session_request",
		},
		"missing userSessionCookieName": {
			APIBaseURL:                  "http://localhost:3001",
			ResourceSessionRequestParam: "p_session_request",
		},
		"missing resourceSessionRequestParam": {
			APIBaseURL:            "http://localhost:3001",
			UserSessionCookieName: "p_session_token",
		},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			cfg.DisableDefaultCFIPs = true
			if _, err := badger.New(context.Background(), nil, cfg, "test"); err == nil {
				t.Fatalf("expected error for %q, got nil", name)
			}
		})
	}
}

func TestNewSucceedsWhenForwardAuthDisabled(t *testing.T) {
	cfg := &badger.Config{
		DisableForwardAuth:  true,
		DisableDefaultCFIPs: true,
	}
	h, err := badger.New(context.Background(), http.NotFoundHandler(), cfg, "test")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestNewRejectsInvalidCIDR(t *testing.T) {
	cfg := &badger.Config{
		DisableForwardAuth:  true,
		DisableDefaultCFIPs: true,
		TrustIP:             []string{"not-a-cidr"},
	}
	if _, err := badger.New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
		t.Fatal("expected error for invalid CIDR, got nil")
	}
}

func TestServeHTTPDisableForwardAuthCallsNext(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		called = true
		rw.WriteHeader(http.StatusOK)
	})
	cfg := &badger.Config{DisableForwardAuth: true, DisableDefaultCFIPs: true}
	h := newTestHandler(t, cfg, next)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	h.ServeHTTP(rw, req)

	if !called {
		t.Fatal("expected next handler to be called")
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rw.Code)
	}
}

func TestRealIPUntrustedUsesDirectIPAndStripsCFHeaders(t *testing.T) {
	var forwarded *http.Request
	next := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		forwarded = req
	})
	cfg := &badger.Config{DisableForwardAuth: true, DisableDefaultCFIPs: true}
	h := newTestHandler(t, cfg, next)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "198.51.100.7:9999"
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got := forwarded.Header.Get("X-Real-Ip"); got != "198.51.100.7" {
		t.Fatalf("expected X-Real-Ip from direct remote addr, got %q", got)
	}
	if got := forwarded.Header.Get("CF-Connecting-IP"); got != "" {
		t.Fatalf("expected CF-Connecting-IP to be stripped for untrusted source, got %q", got)
	}
}

func TestRealIPTrustedProxyUsesCustomHeader(t *testing.T) {
	var forwarded *http.Request
	next := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		forwarded = req
	})
	cfg := &badger.Config{
		DisableForwardAuth:  true,
		DisableDefaultCFIPs: true,
		TrustIP:             []string{"192.0.2.0/24"},
		CustomIPHeader:      "X-Custom-IP",
	}
	h := newTestHandler(t, cfg, next)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("X-Custom-IP", "203.0.113.5")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got := forwarded.Header.Get("X-Forwarded-For"); got != "203.0.113.5" {
		t.Fatalf("expected X-Forwarded-For from custom header, got %q", got)
	}
	if got := forwarded.Header.Get("X-Real-Ip"); got != "203.0.113.5" {
		t.Fatalf("expected X-Real-Ip from custom header, got %q", got)
	}
}

func TestStripSessionCookiesPreservesUnrelated(t *testing.T) {
	verify := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/badger/verify-session" {
			http.Error(rw, "unexpected path", http.StatusNotFound)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"data":{"valid":true}}`))
	}))
	defer verify.Close()

	var forwarded *http.Request
	next := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		forwarded = req
	})
	cfg := &badger.Config{
		APIBaseURL:                  verify.URL,
		UserSessionCookieName:       "p_session_token",
		ResourceSessionRequestParam: "p_session_request",
		DisableDefaultCFIPs:         true,
	}
	h := newTestHandler(t, cfg, next)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Cookie", "p_session_token=secret; other=keep")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if forwarded == nil {
		t.Fatal("expected next handler to be called for valid session")
	}
	cookie := forwarded.Header.Get("Cookie")
	if strings.Contains(cookie, "p_session_token") {
		t.Fatalf("expected session cookie to be stripped, got %q", cookie)
	}
	if !strings.Contains(cookie, "other=keep") {
		t.Fatalf("expected unrelated cookie to be preserved, got %q", cookie)
	}
}
