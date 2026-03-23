package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Monet/seki/internal/storage"
)

// registerOrgRoutes registers org-related admin API routes on the given mux.
func (h *Handler) registerOrgRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/orgs", h.handleCreateOrg)
	mux.HandleFunc("GET /api/v1/orgs", h.handleListOrgs)
	mux.HandleFunc("GET /api/v1/orgs/{slug}", h.handleGetOrg)
	mux.HandleFunc("PATCH /api/v1/orgs/{slug}", h.handleUpdateOrg)
	mux.HandleFunc("DELETE /api/v1/orgs/{slug}", h.handleDeleteOrg)

	mux.HandleFunc("POST /api/v1/orgs/{slug}/members", h.handleAddMember)
	mux.HandleFunc("GET /api/v1/orgs/{slug}/members", h.handleListMembers)
	mux.HandleFunc("DELETE /api/v1/orgs/{slug}/members/{user_id}", h.handleRemoveMember)
	mux.HandleFunc("PATCH /api/v1/orgs/{slug}/members/{user_id}", h.handleUpdateMemberRole)
}

// ---------------------------------------------------------------------------
// Org CRUD
// ---------------------------------------------------------------------------

type createOrgRequest struct {
	ID       string          `json:"id"`
	Slug     string          `json:"slug"`
	Name     string          `json:"name"`
	Domains  []string        `json:"domains"`
	Metadata json.RawMessage `json:"metadata"`
}

func (h *Handler) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var req createOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Slug == "" {
		writeProblem(w, http.StatusBadRequest, "slug is required")
		return
	}
	if req.Name == "" {
		writeProblem(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.ID == "" {
		req.ID = fmt.Sprintf("org_%s", req.Slug)
	}

	now := time.Now().UTC()
	org := &storage.Organization{
		ID:        req.ID,
		Slug:      req.Slug,
		Name:      req.Name,
		Domains:   req.Domains,
		Metadata:  req.Metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if org.Domains == nil {
		org.Domains = []string{}
	}
	if len(org.Metadata) == 0 {
		org.Metadata = json.RawMessage(`{}`)
	}

	if err := h.store.CreateOrg(r.Context(), org); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeProblem(w, http.StatusConflict, "organization already exists")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to create organization")
		return
	}

	writeJSON(w, http.StatusCreated, org)
}

func (h *Handler) handleGetOrg(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, org)
}

type updateOrgRequest struct {
	Name     *string          `json:"name"`
	Slug     *string          `json:"slug"`
	Domains  []string         `json:"domains"`
	Metadata *json.RawMessage `json:"metadata"`
}

func (h *Handler) handleUpdateOrg(w http.ResponseWriter, r *http.Request) {
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

	var req updateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name != nil {
		org.Name = *req.Name
	}
	if req.Slug != nil {
		org.Slug = *req.Slug
	}
	if req.Domains != nil {
		org.Domains = req.Domains
	}
	if req.Metadata != nil {
		org.Metadata = *req.Metadata
	}

	if err := h.store.UpdateOrg(r.Context(), org); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeProblem(w, http.StatusConflict, "slug already taken")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to update organization")
		return
	}

	writeJSON(w, http.StatusOK, org)
}

func (h *Handler) handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
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

	if err := h.store.DeleteOrg(r.Context(), org.ID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "organization not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to delete organization")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type orgListResponse struct {
	Data       []*storage.Organization `json:"data"`
	NextCursor string                  `json:"next_cursor,omitempty"`
}

func (h *Handler) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	opts := storage.ListOptions{
		Cursor: r.URL.Query().Get("cursor"),
	}
	orgs, nextCursor, err := h.store.ListOrgs(r.Context(), opts)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "failed to list organizations")
		return
	}
	if orgs == nil {
		orgs = []*storage.Organization{}
	}
	writeJSON(w, http.StatusOK, orgListResponse{
		Data:       orgs,
		NextCursor: nextCursor,
	})
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

type addMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func (h *Handler) handleAddMember(w http.ResponseWriter, r *http.Request) {
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

	var req addMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.UserID == "" {
		writeProblem(w, http.StatusBadRequest, "user_id is required")
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}

	member := &storage.OrgMember{
		OrgID:    org.ID,
		UserID:   req.UserID,
		Role:     req.Role,
		JoinedAt: time.Now().UTC(),
	}
	if err := h.store.AddMember(r.Context(), member); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeProblem(w, http.StatusConflict, "member already exists")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to add member")
		return
	}

	writeJSON(w, http.StatusCreated, member)
}

func (h *Handler) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	userID := r.PathValue("user_id")
	org, err := h.store.GetOrgBySlug(r.Context(), slug)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "organization not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get organization")
		return
	}

	if err := h.store.RemoveMember(r.Context(), org.ID, userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "member not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to remove member")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type memberListResponse struct {
	Data []*storage.OrgMember `json:"data"`
}

func (h *Handler) handleListMembers(w http.ResponseWriter, r *http.Request) {
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

	members, err := h.store.ListMembers(r.Context(), org.ID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "failed to list members")
		return
	}
	if members == nil {
		members = []*storage.OrgMember{}
	}
	writeJSON(w, http.StatusOK, memberListResponse{Data: members})
}

type updateMemberRoleRequest struct {
	Role string `json:"role"`
}

func (h *Handler) handleUpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	userID := r.PathValue("user_id")
	org, err := h.store.GetOrgBySlug(r.Context(), slug)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "organization not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get organization")
		return
	}

	var req updateMemberRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Role == "" {
		writeProblem(w, http.StatusBadRequest, "role is required")
		return
	}

	if err := h.store.UpdateMemberRole(r.Context(), org.ID, userID, req.Role); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "member not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to update member role")
		return
	}

	member, err := h.store.GetMembership(r.Context(), org.ID, userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "failed to get membership")
		return
	}
	writeJSON(w, http.StatusOK, member)
}
