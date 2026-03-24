package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recovery returns middleware that catches panics from downstream handlers,
// logs the error and stack trace at error level, and returns a 500 response
// with a generic message. Stack traces are never exposed to the client.
func Recovery() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					stack := debug.Stack()

					attrs := []any{
						"error", err,
						"method", r.Method,
						"path", r.URL.Path,
						"stack", string(stack),
					}

					reqID := GetRequestID(r.Context())
					if reqID != "" {
						attrs = append(attrs, "request_id", reqID)
					}

					slog.Error("panic recovered", attrs...)

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error":"internal server error"}`))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
