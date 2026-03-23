package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Monet/seki/internal/storage"
)

// registerRoleRoutes registers role-related admin API routes on the given mux.
func (h *Handler) registerRoleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/orgs/{slug}/roles", h.handleCreateRole)
	mux.HandleFunc("GET /api/v1/orgs/{slug}/roles", h.handleListRoles)
	mux.HandleFunc("PATCH /api/v1/orgs/{slug}/roles/{name}", h.handleUpdateRole)
	mux.HandleFunc("DELETE /api/v1/orgs/{slug}/roles/{name}", h.handleDeleteRole)
}

type createRoleRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

func (h *Handler) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	org, err := h.store.GetOrgBySlug(r.Context(), slug)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "organization not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get organization")
		return
	}

	var req createRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeProblem(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.ID == "" {
		req.ID = fmt.Sprintf("role_%s_%s", org.Slug, req.Name)
	}

	role := &storage.Role{
		ID:          req.ID,
		OrgID:       org.ID,
		Name:        req.Name,
		Permissions: req.Permissions,
		CreatedAt:   time.Now().UTC(),
	}
	if role.Permissions == nil {
		role.Permissions = []string{}
	}

	if err := h.store.CreateRole(r.Context(), role); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeProblem(w, http.StatusConflict, "role already exists")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to create role")
		return
	}

	writeJSON(w, http.StatusCreated, role)
}

type roleListResponse struct {
	Data []*storage.Role `json:"data"`
}

func (h *Handler) handleListRoles(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	org, err := h.store.GetOrgBySlug(r.Context(), slug)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "organization not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get organization")
		return
	}

	roles, err := h.store.ListRoles(r.Context(), org.ID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "failed to list roles")
		return
	}
	if roles == nil {
		roles = []*storage.Role{}
	}
	writeJSON(w, http.StatusOK, roleListResponse{Data: roles})
}

type updateRoleRequest struct {
	Permissions []string `json:"permissions"`
}

func (h *Handler) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	roleName := r.PathValue("name")
	org, err := h.store.GetOrgBySlug(r.Context(), slug)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "organization not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get organization")
		return
	}

	role, err := h.store.GetRoleByName(r.Context(), org.ID, roleName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "role not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get role")
		return
	}

	var req updateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Permissions != nil {
		role.Permissions = req.Permissions
	}

	if err := h.store.UpdateRole(r.Context(), role); err != nil {
		writeProblem(w, http.StatusInternalServerError, "failed to update role")
		return
	}

	writeJSON(w, http.StatusOK, role)
}

func (h *Handler) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	roleName := r.PathValue("name")
	org, err := h.store.GetOrgBySlug(r.Context(), slug)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "organization not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get organization")
		return
	}

	role, err := h.store.GetRoleByName(r.Context(), org.ID, roleName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "role not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get role")
		return
	}

	if err := h.store.DeleteRole(r.Context(), role.ID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "role not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to delete role")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
