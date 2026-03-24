package middleware

import (
	"net/http"
	"strings"

	"github.com/Monet/seki/internal/validate"
)

// tokenPaths lists path prefixes for token/auth endpoints that should
// receive no-cache headers.
var tokenPaths = []string{
	"/oauth/token",
	"/oauth/authorize",
	"/token",
	"/auth/",
	"/login",
}

// SecurityHeaders returns middleware that sets security-related HTTP headers
// on all responses. Additional headers are applied based on the request path:
// HTML-serving endpoints get a Content-Security-Policy header, and token/auth
// endpoints get Cache-Control: no-store.
func SecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Universal security headers.
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("X-XSS-Protection", "0")

			path := r.URL.Path

			// CSP for HTML-serving endpoints (login page).
			if isHTMLPath(path) {
				w.Header().Set("Content-Security-Policy",
					"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
			}

			// No-cache for token/auth endpoints.
			if isTokenPath(path) {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Pragma", "no-cache")
			}

			// Limit request body size on all POST/PUT/PATCH requests to
			// prevent denial-of-service via oversized payloads.
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
				r.Body = http.MaxBytesReader(w, r.Body, int64(validate.MaxJSONBodyBytes))
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isHTMLPath returns true for paths that serve HTML content.
func isHTMLPath(path string) bool {
	return path == "/login" ||
		strings.HasPrefix(path, "/login/") ||
		path == "/authorize" ||
		path == "/consent"
}

// isTokenPath returns true for token and auth endpoints.
func isTokenPath(path string) bool {
	for _, prefix := range tokenPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
