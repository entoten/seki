package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/internal/validate"
)

// createUserRequest is the JSON body for POST /api/v1/users.
type createUserRequest struct {
	Email       string          `json:"email"`
	DisplayName string          `json:"display_name"`
	Metadata    json.RawMessage `json:"metadata"`
}

// updateUserRequest is the JSON body for PATCH /api/v1/users/{id}.
type updateUserRequest struct {
	Email       *string          `json:"email"`
	DisplayName *string          `json:"display_name"`
	Disabled    *bool            `json:"disabled"`
	Metadata    *json.RawMessage `json:"metadata"`
}

// userListResponse is the JSON envelope for GET /api/v1/users.
type userListResponse struct {
	Users      []*storage.User `json:"users"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := validate.Email(req.Email); err != nil {
		writeProblem(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validate.DisplayName(req.DisplayName); err != nil {
		writeProblem(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validate.Metadata(req.Metadata); err != nil {
		writeProblem(w, http.StatusBadRequest, err.Error())
		return
	}

	now := time.Now().UTC().Truncate(time.Second)
	user := &storage.User{
		ID:          uuid.New().String(),
		Email:       req.Email,
		DisplayName: req.DisplayName,
		Metadata:    req.Metadata,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if len(user.Metadata) == 0 {
		user.Metadata = json.RawMessage(`{}`)
	}

	if err := h.store.CreateUser(r.Context(), user); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeProblem(w, http.StatusConflict, "email already exists")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(user)
}

func (h *Handler) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "user not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(user)
}

func (h *Handler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// If email filter is specified, use exact lookup.
	if email := q.Get("email"); email != "" {
		user, err := h.store.GetUserByEmail(r.Context(), email)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeJSON(w, http.StatusOK, userListResponse{Users: []*storage.User{}})
				return
			}
			writeProblem(w, http.StatusInternalServerError, "failed to search users")
			return
		}
		writeJSON(w, http.StatusOK, userListResponse{Users: []*storage.User{user}})
		return
	}

	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 100 {
		limit = 100
	}

	opts := storage.ListOptions{
		Cursor: q.Get("cursor"),
		Limit:  limit,
	}

	users, nextCursor, err := h.store.ListUsers(r.Context(), opts)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	if users == nil {
		users = []*storage.User{}
	}

	writeJSON(w, http.StatusOK, userListResponse{
		Users:      users,
		NextCursor: nextCursor,
	})
}

func (h *Handler) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	existing, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "user not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email != nil {
		if err := validate.Email(*req.Email); err != nil {
			writeProblem(w, http.StatusBadRequest, err.Error())
			return
		}
		existing.Email = *req.Email
	}
	if req.DisplayName != nil {
		if err := validate.DisplayName(*req.DisplayName); err != nil {
			writeProblem(w, http.StatusBadRequest, err.Error())
			return
		}
		existing.DisplayName = *req.DisplayName
	}
	if req.Disabled != nil {
		existing.Disabled = *req.Disabled
	}
	if req.Metadata != nil {
		if err := validate.Metadata(*req.Metadata); err != nil {
			writeProblem(w, http.StatusBadRequest, err.Error())
			return
		}
		existing.Metadata = *req.Metadata
	}

	if err := h.store.UpdateUser(r.Context(), existing); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeProblem(w, http.StatusConflict, "email already exists")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to update user")
		return
	}

	// Re-fetch to get the updated_at value set by the store.
	updated, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "failed to get updated user")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

func (h *Handler) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.DeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "user not found")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
