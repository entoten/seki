package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/entoten/seki/internal/config"
)

// defaultAllowedMethods are used when CORSConfig.AllowedMethods is empty.
var defaultAllowedMethods = []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"}

// defaultAllowedHeaders are used when CORSConfig.AllowedHeaders is empty.
var defaultAllowedHeaders = []string{"Authorization", "Content-Type", "X-API-Key"}

// defaultMaxAge is used when CORSConfig.MaxAge is zero.
const defaultMaxAge = 3600

// CORS returns middleware that handles Cross-Origin Resource Sharing.
// It validates the request Origin against the configured allowed origins and
// sets the appropriate CORS response headers. Preflight OPTIONS requests are
// handled and short-circuited with a 204 response.
func CORS(cfg config.CORSConfig) func(http.Handler) http.Handler {
	methods := cfg.AllowedMethods
	if len(methods) == 0 {
		methods = defaultAllowedMethods
	}

	headers := cfg.AllowedHeaders
	if len(headers) == 0 {
		headers = defaultAllowedHeaders
	}

	maxAge := cfg.MaxAge
	if maxAge == 0 {
		maxAge = defaultMaxAge
	}

	allowCredentials := cfg.AllowCredentials

	// Build a set for fast origin lookup.
	originSet := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		originSet[o] = struct{}{}
	}

	methodsStr := strings.Join(methods, ", ")
	headersStr := strings.Join(headers, ", ")
	maxAgeStr := strconv.Itoa(maxAge)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Only set CORS headers if the origin is in the allowed list.
			if origin != "" {
				if _, ok := originSet[origin]; ok {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", methodsStr)
					w.Header().Set("Access-Control-Allow-Headers", headersStr)
					w.Header().Set("Access-Control-Max-Age", maxAgeStr)
					if allowCredentials {
						w.Header().Set("Access-Control-Allow-Credentials", "true")
					}
					w.Header().Set("Vary", "Origin")
				}
			}

			// Handle preflight.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
