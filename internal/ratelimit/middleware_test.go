package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Monet/seki/internal/config"
)

func TestHTTPMiddleware_AllowsTraffic(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:        true,
		RequestsPerMin: 100,
	}
	limiter := NewLimiter(cfg)
	defer limiter.Stop()

	handler := HTTPMiddleware(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHTTPMiddleware_BlocksExcess(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:        true,
		RequestsPerMin: 2,
	}
	limiter := NewLimiter(cfg)
	defer limiter.Stop()

	handler := HTTPMiddleware(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First 2 requests should pass.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, rec.Code)
		}
	}

	// Third request should be rate limited.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}

	// Check response body.
	var body map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body["title"] != "Too Many Requests" {
		t.Errorf("title = %v", body["title"])
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Errorf("Retry-After = %s", rec.Header().Get("Retry-After"))
	}
}

func TestHTTPMiddleware_SkipsHealthz(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:        true,
		RequestsPerMin: 1,
	}
	limiter := NewLimiter(cfg)
	defer limiter.Stop()

	handler := HTTPMiddleware(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Use up the rate limit.
	req := httptest.NewRequest(http.MethodGet, "/something", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// /healthz should still work.
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: expected 200, got %d", rec.Code)
	}
}

func TestClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	if got := clientIP(req); got != "1.2.3.4" {
		t.Errorf("clientIP = %q, want 1.2.3.4", got)
	}
}

func TestClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "9.8.7.6")
	if got := clientIP(req); got != "9.8.7.6" {
		t.Errorf("clientIP = %q, want 9.8.7.6", got)
	}
}

func TestClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "11.22.33.44:5678"
	if got := clientIP(req); got != "11.22.33.44" {
		t.Errorf("clientIP = %q, want 11.22.33.44", got)
	}
}
