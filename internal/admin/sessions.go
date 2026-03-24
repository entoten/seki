package admin

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Monet/seki/internal/storage"
)

// sessionListResponse is the JSON envelope for GET /api/v1/users/{id}/sessions.
type sessionListResponse struct {
	Sessions []*storage.Session `json:"sessions"`
}

// registerSessionRoutesOn registers session-related admin API routes on the given mux.
func (h *Handler) registerSessionRoutesOn(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/users/{id}/sessions", h.handleListUserSessions)
	mux.HandleFunc("DELETE /api/v1/users/{id}/sessions/{session_id}", h.handleRevokeUserSession)
}

func (h *Handler) handleListUserSessions(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	// Verify user exists.
	if _, err := h.store.GetUser(r.Context(), userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "user not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	sessions, err := h.store.ListSessionsByUserID(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}
	if sessions == nil {
		sessions = []*storage.Session{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessionListResponse{Sessions: sessions})
}

func (h *Handler) handleRevokeUserSession(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	sessionID := r.PathValue("session_id")

	// Verify user exists.
	if _, err := h.store.GetUser(r.Context(), userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "user not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	// Verify the session belongs to this user.
	sess, err := h.store.GetSession(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "session not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get session")
		return
	}
	if sess.UserID != userID {
		writeProblem(w, http.StatusNotFound, "session not found")
		return
	}

	if err := h.store.DeleteSession(r.Context(), sessionID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "session not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to revoke session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
