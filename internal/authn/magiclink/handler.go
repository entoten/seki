package magiclink

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/entoten/seki/internal/session"
)

// oidcParamKeys are the OIDC authorization parameters to preserve through the login flow.
var oidcParamKeys = []string{
	"client_id",
	"redirect_uri",
	"response_type",
	"scope",
	"state",
	"nonce",
	"code_challenge",
	"code_challenge_method",
}

// Handler provides HTTP handlers for magic link authentication.
type Handler struct {
	svc      *Service
	sessions *session.Manager
}

// NewHandler creates a new magic link Handler.
func NewHandler(svc *Service, sessions *session.Manager) *Handler {
	return &Handler{svc: svc, sessions: sessions}
}

// RegisterRoutes registers magic link routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /authn/magiclink/request", h.handleRequest)
	mux.HandleFunc("POST /authn/magiclink/verify", h.handleVerifyCode)
	mux.HandleFunc("GET /authn/magiclink/verify", h.handleVerifyMagicLink)
}

// requestBody is the JSON body for POST /authn/magiclink/request.
type requestBody struct {
	Email string `json:"email"`
}

// verifyBody is the JSON body for POST /authn/magiclink/verify.
type verifyBody struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// handleRequest handles POST /authn/magiclink/request.
func (h *Handler) handleRequest(w http.ResponseWriter, r *http.Request) {
	var body requestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	_, err := h.svc.RequestCode(r.Context(), body.Email)
	if err != nil {
		if err == ErrRateLimited {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests, please try again later"})
			return
		}
		// For user not found, return 200 anyway to prevent enumeration.
		if err == ErrUserNotFound {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleVerifyCode handles POST /authn/magiclink/verify.
func (h *Handler) handleVerifyCode(w http.ResponseWriter, r *http.Request) {
	var body verifyBody

	// Support both JSON and form-encoded.
	ct := r.Header.Get("Content-Type")
	if ct == "application/x-www-form-urlencoded" || ct == "multipart/form-data" {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form"})
			return
		}
		body.Email = r.FormValue("email")
		body.Code = r.FormValue("code")
	} else {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
	}

	if body.Email == "" || body.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and code are required"})
		return
	}

	user, err := h.svc.VerifyCode(r.Context(), body.Email, body.Code)
	if err != nil {
		status := http.StatusUnauthorized
		msg := "invalid or expired code"
		if err == ErrTooManyAttempts {
			status = http.StatusTooManyRequests
			msg = "too many verification attempts"
		}
		writeJSON(w, status, map[string]string{"error": msg})
		return
	}

	h.completeLogin(w, r, user.ID)
}

// handleVerifyMagicLink handles GET /authn/magiclink/verify?token=...
func (h *Handler) handleVerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	user, err := h.svc.VerifyMagicLink(r.Context(), token)
	if err != nil {
		status := http.StatusUnauthorized
		msg := "invalid or expired token"
		if err == ErrTooManyAttempts {
			status = http.StatusTooManyRequests
			msg = "too many verification attempts"
		}
		http.Error(w, msg, status)
		return
	}

	h.completeLogin(w, r, user.ID)
}

// completeLogin creates a session and redirects to /authorize if OIDC params are present.
func (h *Handler) completeLogin(w http.ResponseWriter, r *http.Request, userID string) {
	if h.sessions == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session manager not configured"})
		return
	}

	sess, err := h.sessions.Create(r.Context(), userID, "", r.RemoteAddr, r.UserAgent())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
		return
	}
	h.sessions.SetCookie(w, sess)

	// Check for OIDC params to redirect back to /authorize.
	redirectURL := buildAuthorizeRedirect(r)
	if redirectURL != "" {
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "authenticated"})
}

// buildAuthorizeRedirect reconstructs the /authorize URL from OIDC query/form values.
func buildAuthorizeRedirect(r *http.Request) string {
	q := url.Values{}
	for _, key := range oidcParamKeys {
		var v string
		// Check form values first (POST), then query (GET).
		if r.Method == http.MethodPost {
			v = r.FormValue(key)
		}
		if v == "" {
			v = r.URL.Query().Get(key)
		}
		if v != "" {
			q.Set(key, v)
		}
	}
	if q.Get("client_id") == "" {
		return ""
	}
	return "/authorize?" + q.Encode()
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
