package password

import (
	"encoding/json"
	"net/http"

	"github.com/entoten/seki/internal/storage"
)

// Handler provides HTTP handlers for password authentication.
type Handler struct {
	service *Service
	store   storage.Storage
}

// NewHandler creates a new password HTTP handler.
func NewHandler(service *Service, store storage.Storage) *Handler {
	return &Handler{
		service: service,
		store:   store,
	}
}

// RegisterRoutes registers password HTTP routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /authn/password/register", h.handleRegister)
	mux.HandleFunc("POST /authn/password/verify", h.handleVerify)
	mux.HandleFunc("POST /authn/password/change", h.handleChange)
}

// registerRequest is the JSON request body for the register endpoint.
type registerRequest struct {
	Password string `json:"password"`
}

// verifyRequest is the JSON request body for the verify endpoint.
type verifyRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// changeRequest is the JSON request body for the change password endpoint.
type changeRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// handleRegister registers a password for the authenticated user.
func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password is required"})
		return
	}

	err := h.service.Register(r.Context(), userID, req.Password)
	if err != nil {
		if err == ErrPasswordTooShort || err == ErrPasswordTooLong {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to register password"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_registered"})
}

// handleVerify verifies a password during login.
func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password are required"})
		return
	}

	user, err := h.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		// Return generic error to avoid user enumeration.
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	err = h.service.Verify(r.Context(), user.ID, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "verified",
		"user_id": user.ID,
	})
}

// handleChange changes the password for the authenticated user.
func (h *Handler) handleChange(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	var req changeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "old_password and new_password are required"})
		return
	}

	err := h.service.ChangePassword(r.Context(), userID, req.OldPassword, req.NewPassword)
	if err != nil {
		switch err {
		case ErrPasswordTooShort, ErrPasswordTooLong:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		case ErrInvalidPassword:
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid old password"})
		case ErrNotConfigured:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password not configured"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to change password"})
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
