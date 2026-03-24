package admin

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/entoten/seki/internal/middleware"
)

// ProblemDetail represents an RFC 7807 Problem Details response.
type ProblemDetail struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Code     string `json:"code,omitempty"`     // machine-readable error code
	Instance string `json:"instance,omitempty"` // request ID
}

// writeProblem writes an RFC 7807 Problem Details JSON response.
// The code parameter is a machine-readable error code (e.g. ErrCodeUserNotFound).
// If r is non-nil, the request ID is populated from the context.
func writeProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	typ := "about:blank"
	if code != "" {
		typ = fmt.Sprintf("https://seki.dev/errors/%s", code)
	}

	var instance string
	if r != nil {
		instance = middleware.GetRequestID(r.Context())
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ProblemDetail{
		Type:     typ,
		Title:    http.StatusText(status),
		Status:   status,
		Detail:   detail,
		Code:     code,
		Instance: instance,
	})
}
