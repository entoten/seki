package admin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/entoten/seki/internal/audit"
	"github.com/entoten/seki/internal/storage"
)

// impersonateResponse is the JSON body returned by POST /api/v1/users/{id}/impersonate.
type impersonateResponse struct {
	SessionID   string `json:"session_id"`
	CookieValue string `json:"cookie_value"`
	ExpiresAt   string `json:"expires_at"`
}

// registerImpersonateRoutesOn registers the impersonation route on the given mux.
func (h *Handler) registerImpersonateRoutesOn(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/users/{id}/impersonate", h.handleImpersonate)
}

func (h *Handler) handleImpersonate(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	// Verify user exists.
	if _, err := h.store.GetUser(r.Context(), userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, r, http.StatusNotFound, ErrCodeUserNotFound, "user not found")
			return
		}
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to get user")
		return
	}

	// Generate a secure session ID.
	sessionID, err := generateSessionID()
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to generate session")
		return
	}

	// Derive impersonator identifier from the API key used.
	impersonatorID := "admin"
	apiKey := extractAPIKey(r)
	if apiKey != "" {
		impersonatorID = fmt.Sprintf("admin-api-key-%s", shortHash(apiKey))
	}

	// Build impersonation metadata.
	meta, _ := json.Marshal(map[string]interface{}{
		"impersonated":    true,
		"impersonator_id": impersonatorID,
	})

	now := time.Now().UTC()
	ttl := 1 * time.Hour

	sess := &storage.Session{
		ID:                sessionID,
		UserID:            userID,
		ClientID:          "admin-impersonation",
		IPAddress:         r.RemoteAddr,
		UserAgent:         r.UserAgent(),
		Metadata:          meta,
		CreatedAt:         now,
		ExpiresAt:         now.Add(ttl),
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(ttl),
	}

	if err := h.store.CreateSession(r.Context(), sess); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to create impersonation session")
		return
	}

	// Audit log the impersonation event.
	if h.audit != nil {
		_ = h.audit.LogAdmin(r.Context(), audit.EventUserImpersonated, "admin", "user", userID, map[string]interface{}{
			"impersonator_id": impersonatorID,
			"session_id":      sessionID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(impersonateResponse{
		SessionID:   sessionID,
		CookieValue: sessionID,
		ExpiresAt:   sess.ExpiresAt.Format(time.RFC3339),
	})
}

// generateSessionID creates a cryptographically random URL-safe session ID.
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("impersonate: generate session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// shortHash returns a truncated representation of the API key for audit purposes.
// It avoids storing the full key while still allowing correlation.
func shortHash(key string) string {
	if len(key) <= 8 {
		return "***"
	}
	return key[:4] + "..." + key[len(key)-4:]
}
