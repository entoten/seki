package admin

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// RequireAPIKey returns middleware that enforces API key authentication on
// every request. Keys are accepted via the Authorization header (Bearer
// scheme) or via the X-API-Key header. Comparison is constant-time.
//
// If apiKeys is empty, all requests are allowed through (no auth configured).
func RequireAPIKey(apiKeys []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// When no keys are configured, skip authentication.
			if len(apiKeys) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			key := extractAPIKey(r)
			if key == "" {
				writeProblem(w, r, http.StatusUnauthorized, ErrCodeUnauthorized, "missing API key")
				return
			}

			if !validKey(key, apiKeys) {
				writeProblem(w, r, http.StatusUnauthorized, ErrCodeUnauthorized, "invalid API key")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractAPIKey reads the API key from either the Authorization header
// (Bearer scheme) or the X-API-Key header.
func extractAPIKey(r *http.Request) string {
	// Try Authorization: Bearer <key> first.
	if auth := r.Header.Get("Authorization"); auth != "" {
		const prefix = "Bearer "
		if strings.HasPrefix(auth, prefix) {
			return auth[len(prefix):]
		}
	}

	// Fall back to X-API-Key header.
	return r.Header.Get("X-API-Key")
}

// validKey checks the supplied key against configured keys using
// constant-time comparison to prevent timing attacks.
func validKey(key string, apiKeys []string) bool {
	for _, k := range apiKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(k)) == 1 {
			return true
		}
	}
	return false
}
