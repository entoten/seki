package metrics

import (
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// uuidPattern matches UUIDs in URL paths.
var uuidPattern = regexp.MustCompile(
	`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
)

// numericIDPattern matches purely numeric path segments (e.g. /users/42).
var numericIDPattern = regexp.MustCompile(`/\d+(?:/|$)`)

// NormalizePath replaces UUIDs and numeric IDs in a path with {id}.
func NormalizePath(path string) string {
	path = uuidPattern.ReplaceAllString(path, "{id}")
	path = numericIDPattern.ReplaceAllStringFunc(path, func(match string) string {
		if match[len(match)-1] == '/' {
			return "/{id}/"
		}
		return "/{id}"
	})
	return path
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.statusCode = http.StatusOK
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

// Middleware returns an HTTP middleware that records request metrics.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()
		path := NormalizePath(r.URL.Path)

		HTTPRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(rw.statusCode)).Inc()
		HTTPRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
	})
}
