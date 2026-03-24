package validate

import (
	"io"
	"net/http"
)

// LimitedReader returns an io.ReadCloser that limits the number of bytes
// read from the request body to MaxJSONBodyBytes. Handlers should use this
// before json.NewDecoder to prevent DoS via huge payloads.
func LimitedReader(r *http.Request) io.ReadCloser {
	return http.MaxBytesReader(nil, r.Body, int64(MaxJSONBodyBytes))
}

// LimitBody replaces r.Body with a size-limited reader. Call this at the
// start of any handler that decodes a JSON request body.
func LimitBody(r *http.Request) {
	r.Body = http.MaxBytesReader(nil, r.Body, int64(MaxJSONBodyBytes))
}
