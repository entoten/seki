package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// requestIDKey is the context key for the request ID.
type requestIDKey struct{}

// RequestIDHeader is the HTTP header used for request ID tracking.
const RequestIDHeader = "X-Request-ID"

// RequestID returns middleware that assigns a unique request ID to each request.
// If the incoming request already has an X-Request-ID header (e.g., from a
// reverse proxy), that value is reused. Otherwise a new UUID is generated.
// The request ID is added to the response headers and stored in the request
// context.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(RequestIDHeader)
			if id == "" {
				id = uuid.New().String()
			}

			w.Header().Set(RequestIDHeader, id)

			ctx := context.WithValue(r.Context(), requestIDKey{}, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetRequestID extracts the request ID from the context.
// Returns an empty string if no request ID is present.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}
