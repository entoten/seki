package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders_Universal(t *testing.T) {
	handler := SecurityHeaders()(newTestHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	tests := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
		{"X-XSS-Protection", "0"},
	}

	for _, tc := range tests {
		if got := rr.Header().Get(tc.header); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestSecurityHeaders_CacheControlOnTokenEndpoint(t *testing.T) {
	handler := SecurityHeaders()(newTestHandler())

	paths := []string{
		"/oauth/token",
		"/oauth/authorize",
		"/token",
		"/auth/callback",
		"/login",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if got := rr.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want %q for path %s", got, "no-store", path)
			}
			if got := rr.Header().Get("Pragma"); got != "no-cache" {
				t.Errorf("Pragma = %q, want %q for path %s", got, "no-cache", path)
			}
		})
	}
}

func TestSecurityHeaders_NoCacheControlOnRegularEndpoint(t *testing.T) {
	handler := SecurityHeaders()(newTestHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control = %q, want empty for non-token endpoint", got)
	}
}

func TestSecurityHeaders_CSPOnHTMLEndpoints(t *testing.T) {
	handler := SecurityHeaders()(newTestHandler())

	paths := []string{
		"/login",
		"/login/callback",
		"/authorize",
		"/consent",
	}

	expectedCSP := "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if got := rr.Header().Get("Content-Security-Policy"); got != expectedCSP {
				t.Errorf("Content-Security-Policy = %q, want %q for path %s", got, expectedCSP, path)
			}
		})
	}
}

func TestSecurityHeaders_NoCSPOnAPIEndpoints(t *testing.T) {
	handler := SecurityHeaders()(newTestHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("Content-Security-Policy = %q, want empty for API endpoint", got)
	}
}
