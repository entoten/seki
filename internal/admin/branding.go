package admin

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/entoten/seki/internal/storage"
)

// registerBrandingRoutesOn registers branding-related admin API routes on the given mux.
func (h *Handler) registerBrandingRoutesOn(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/orgs/{slug}/branding", h.handleGetBranding)
	mux.HandleFunc("PATCH /api/v1/orgs/{slug}/branding", h.handleUpdateBranding)
}

func (h *Handler) handleGetBranding(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	org, err := h.store.GetOrgBySlug(r.Context(), slug)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, r, http.StatusNotFound, ErrCodeOrgNotFound, "organization not found")
			return
		}
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to get organization")
		return
	}
	writeJSON(w, http.StatusOK, org.Branding)
}

type updateBrandingRequest struct {
	LogoURL         *string `json:"logo_url"`
	PrimaryColor    *string `json:"primary_color"`
	BackgroundColor *string `json:"background_color"`
	CustomCSS       *string `json:"custom_css"`
}

func (h *Handler) handleUpdateBranding(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	org, err := h.store.GetOrgBySlug(r.Context(), slug)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, r, http.StatusNotFound, ErrCodeOrgNotFound, "organization not found")
			return
		}
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to get organization")
		return
	}

	var req updateBrandingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body")
		return
	}

	if req.LogoURL != nil {
		org.Branding.LogoURL = *req.LogoURL
	}
	if req.PrimaryColor != nil {
		org.Branding.PrimaryColor = *req.PrimaryColor
	}
	if req.BackgroundColor != nil {
		org.Branding.BackgroundColor = *req.BackgroundColor
	}
	if req.CustomCSS != nil {
		org.Branding.CustomCSS = *req.CustomCSS
	}

	if err := h.store.UpdateOrg(r.Context(), org); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to update branding")
		return
	}

	writeJSON(w, http.StatusOK, org.Branding)
}
