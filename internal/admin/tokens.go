package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Monet/seki/internal/authn/pat"
	"github.com/Monet/seki/internal/storage"
)

// registerPATRoutesOn registers personal access token admin API routes.
func (h *Handler) registerPATRoutesOn(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/users/{id}/tokens", h.handleCreatePAT)
	mux.HandleFunc("GET /api/v1/users/{id}/tokens", h.handleListPATs)
	mux.HandleFunc("DELETE /api/v1/users/{id}/tokens/{token_id}", h.handleDeletePAT)
}

type createPATRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresIn int      `json:"expires_in"` // seconds; 0 defaults to 90 days
}

type createPATResponse struct {
	Token string                       `json:"token"` // shown once
	PAT   *storage.PersonalAccessToken `json:"pat"`
}

type patListResponse struct {
	Tokens []*storage.PersonalAccessToken `json:"tokens"`
}

func (h *Handler) handleCreatePAT(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	// Verify user exists.
	_, err := h.store.GetUser(r.Context(), userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "user not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	var req createPATRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeProblem(w, http.StatusBadRequest, "name is required")
		return
	}

	expiresIn := time.Duration(req.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 90 * 24 * time.Hour // 90 days default
	}
	expiresAt := time.Now().UTC().Add(expiresIn)

	if req.Scopes == nil {
		req.Scopes = []string{}
	}

	svc := pat.NewService(h.store)
	token, p, err := svc.Generate(r.Context(), userID, req.Name, req.Scopes, expiresAt)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	writeJSON(w, http.StatusCreated, createPATResponse{Token: token, PAT: p})
}

func (h *Handler) handleListPATs(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	// Verify user exists.
	_, err := h.store.GetUser(r.Context(), userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "user not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	pats, err := h.store.ListPATsByUser(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "failed to list tokens")
		return
	}
	if pats == nil {
		pats = []*storage.PersonalAccessToken{}
	}

	writeJSON(w, http.StatusOK, patListResponse{Tokens: pats})
}

func (h *Handler) handleDeletePAT(w http.ResponseWriter, r *http.Request) {
	tokenID := r.PathValue("token_id")

	svc := pat.NewService(h.store)
	if err := svc.Revoke(r.Context(), tokenID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "token not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to delete token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
