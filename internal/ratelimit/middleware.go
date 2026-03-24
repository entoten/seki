package ratelimit

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// HTTPMiddleware returns an HTTP middleware that applies general rate limiting
// by client IP address. It skips the /healthz endpoint.
// When the limit is exceeded, it returns 429 Too Many Requests with an
// RFC 7807 problem details response body.
func HTTPMiddleware(limiter *Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip health check endpoint.
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}

			ip := clientIP(r)
			if !limiter.Allow(ip) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"type":   "urn:ietf:rfc:6585#too-many-requests",
					"title":  "Too Many Requests",
					"status": http.StatusTooManyRequests,
					"detail": "Rate limit exceeded. Please try again later.",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the client IP address from the request,
// respecting X-Forwarded-For and X-Real-IP headers.
func clientIP(r *http.Request) string {
	// Check X-Forwarded-For first (may contain comma-separated list).
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Use the first (leftmost) IP, which is the original client.
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP.
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr (strip port).
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
