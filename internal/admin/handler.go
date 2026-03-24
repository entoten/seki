package admin

import (
	"net/http"

	"github.com/Monet/seki/internal/storage"
)

// Handler serves the Admin REST API.
type Handler struct {
	store   storage.Storage
	apiKeys []string
}

// NewHandler creates a new admin API handler backed by the given storage.
func NewHandler(store storage.Storage, apiKeys ...string) *Handler {
	return &Handler{store: store, apiKeys: apiKeys}
}

// RegisterRoutes registers all admin API routes on the given mux.
// All /api/v1/ routes are wrapped with API key authentication middleware.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Build an internal mux for admin API routes so we can wrap them
	// with the auth middleware as a single handler tree.
	api := http.NewServeMux()

	api.HandleFunc("POST /api/v1/users", h.handleCreateUser)
	api.HandleFunc("GET /api/v1/users", h.handleListUsers)
	api.HandleFunc("GET /api/v1/users/{id}", h.handleGetUser)
	api.HandleFunc("PATCH /api/v1/users/{id}", h.handleUpdateUser)
	api.HandleFunc("DELETE /api/v1/users/{id}", h.handleDeleteUser)

	h.registerOrgRoutesOn(api)
	h.registerRoleRoutesOn(api)
	h.registerAuditRoutesOn(api)

	// Wrap with authentication and mount on the outer mux.
	authMiddleware := RequireAPIKey(h.apiKeys)
	mux.Handle("/api/v1/", authMiddleware(api))
}
