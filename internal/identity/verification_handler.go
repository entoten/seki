package identity

import (
	"encoding/json"
	"net/http"
)

// VerificationHandler provides HTTP handlers for email verification and password reset.
type VerificationHandler struct {
	service *VerificationService
}

// NewVerificationHandler creates a new VerificationHandler.
func NewVerificationHandler(service *VerificationService) *VerificationHandler {
	return &VerificationHandler{service: service}
}

// RegisterRoutes registers verification HTTP routes on the given mux.
func (h *VerificationHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /identity/verify-email/request", h.handleRequestEmailVerification)
	mux.HandleFunc("POST /identity/verify-email/confirm", h.handleVerifyEmail)
	mux.HandleFunc("POST /identity/password-reset/request", h.handleRequestPasswordReset)
	mux.HandleFunc("POST /identity/password-reset/confirm", h.handleResetPassword)
}

type emailVerificationConfirmRequest struct {
	Token string `json:"token"`
}

type passwordResetRequest struct {
	Email string `json:"email"`
}

type passwordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (h *VerificationHandler) handleRequestEmailVerification(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	_, err := h.service.RequestEmailVerification(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to request email verification"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "verification_email_requested"})
}

func (h *VerificationHandler) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req emailVerificationConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}

	err := h.service.VerifyEmail(r.Context(), req.Token)
	if err != nil {
		switch err {
		case ErrTokenInvalid:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token"})
		case ErrTokenExpired:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token has expired"})
		case ErrTokenUsed:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token has already been used"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify email"})
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "email_verified"})
}

func (h *VerificationHandler) handleRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	// Always return success to prevent user enumeration.
	_ = h.service.RequestPasswordReset(r.Context(), req.Email)

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_reset_requested"})
}

func (h *VerificationHandler) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req passwordResetConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Token == "" || req.NewPassword == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token and new_password are required"})
		return
	}

	err := h.service.ResetPassword(r.Context(), req.Token, req.NewPassword)
	if err != nil {
		switch err {
		case ErrTokenInvalid:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token"})
		case ErrTokenExpired:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token has expired"})
		case ErrTokenUsed:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token has already been used"})
		case ErrPasswordShort:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to reset password"})
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_reset_complete"})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
