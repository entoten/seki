package social

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// Handler provides HTTP handlers for social login.
type Handler struct {
	service     *Service
	callbackURL string // base URL for callbacks, e.g. "https://example.com"
}

// NewHandler creates a new social login HTTP handler.
func NewHandler(service *Service, callbackURL string) *Handler {
	return &Handler{
		service:     service,
		callbackURL: callbackURL,
	}
}

// RegisterRoutes registers social login HTTP routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /authn/social/{provider}/authorize", h.handleAuthorize)
	mux.HandleFunc("GET /authn/social/{provider}/callback", h.handleCallback)
}

// handleAuthorize redirects the user to the provider's OAuth2 authorization page.
func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")

	state, err := generateState()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate state"})
		return
	}

	redirectURL := h.callbackURL + "/authn/social/" + providerName + "/callback"

	authURL, err := h.service.GetAuthURL(providerName, state, redirectURL)
	if err != nil {
		if err == ErrUnknownProvider {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown provider"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to build auth URL"})
		return
	}

	// Set state in a cookie for CSRF verification on callback.
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/authn/social/" + providerName + "/callback",
		MaxAge:   600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	})

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback handles the OAuth2 callback from the provider.
func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")

	// Verify state for CSRF protection.
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing state cookie"})
		return
	}

	queryState := r.URL.Query().Get("state")
	if queryState != stateCookie.Value {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "state mismatch"})
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing authorization code"})
		return
	}

	redirectURL := h.callbackURL + "/authn/social/" + providerName + "/callback"

	socialUser, err := h.service.Exchange(r.Context(), providerName, code, redirectURL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication failed"})
		return
	}

	user, isNew, err := h.service.FindOrCreateUser(r.Context(), socialUser)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to process user"})
		return
	}

	// Link the social account to the user.
	if err := h.service.LinkAccount(r.Context(), socialUser, user.ID); err != nil {
		// Non-fatal: account may already be linked.
		_ = err
	}

	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/authn/social/" + providerName + "/callback",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "authenticated",
		"user_id": user.ID,
		"is_new":  isNew,
	})
}

// generateState creates a cryptographically random state string for CSRF protection.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
