package admin

import (
	"net/http"

	"github.com/Monet/seki/internal/storage"
)

// Handler serves the Admin REST API.
type Handler struct {
	store storage.Storage
}

// NewHandler creates a new admin API handler backed by the given storage.
func NewHandler(store storage.Storage) *Handler {
	return &Handler{store: store}
}

// RegisterRoutes registers all admin API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/users", h.handleCreateUser)
	mux.HandleFunc("GET /api/v1/users", h.handleListUsers)
	mux.HandleFunc("GET /api/v1/users/{id}", h.handleGetUser)
	mux.HandleFunc("PATCH /api/v1/users/{id}", h.handleUpdateUser)
	mux.HandleFunc("DELETE /api/v1/users/{id}", h.handleDeleteUser)

	h.registerOrgRoutes(mux)
	h.registerRoleRoutes(mux)
}
