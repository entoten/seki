package totp

import (
	"encoding/json"
	"net/http"

	"github.com/entoten/seki/internal/storage"
)

// Handler provides HTTP handlers for TOTP registration and verification.
type Handler struct {
	service *Service
	store   storage.Storage
}

// NewHandler creates a new TOTP HTTP handler.
func NewHandler(service *Service, store storage.Storage) *Handler {
	return &Handler{
		service: service,
		store:   store,
	}
}

// RegisterRoutes registers TOTP HTTP routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /authn/totp/setup/begin", h.handleSetupBegin)
	mux.HandleFunc("POST /authn/totp/setup/finish", h.handleSetupFinish)
	mux.HandleFunc("POST /authn/totp/verify", h.handleVerify)
	mux.HandleFunc("POST /authn/totp/recovery", h.handleRecovery)
}

// setupBeginResponse is the JSON response from the setup begin endpoint.
type setupBeginResponse struct {
	OTPAuthURI    string   `json:"otpauth_uri"`
	Secret        string   `json:"secret"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// setupFinishRequest is the JSON request body for the setup finish endpoint.
type setupFinishRequest struct {
	Code          string   `json:"code"`
	Secret        string   `json:"secret"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// verifyRequest is the JSON request body for the verify endpoint.
type verifyRequest struct {
	UserID string `json:"user_id"`
	Code   string `json:"code"`
}

// recoveryRequest is the JSON request body for the recovery endpoint.
type recoveryRequest struct {
	UserID string `json:"user_id"`
	Code   string `json:"code"`
}

// handleSetupBegin generates a new TOTP secret and recovery codes.
// Requires an authenticated session (user ID from context or session).
func (h *Handler) handleSetupBegin(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	user, err := h.store.GetUser(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get user"})
		return
	}

	key, codes, err := h.service.GenerateSecret(user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate TOTP secret"})
		return
	}

	writeJSON(w, http.StatusOK, setupBeginResponse{
		OTPAuthURI:    key.URL(),
		Secret:        key.Secret(),
		RecoveryCodes: codes,
	})
}

// handleSetupFinish verifies the initial TOTP code and enables TOTP for the user.
func (h *Handler) handleSetupFinish(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	var req setupFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Code == "" || req.Secret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code and secret are required"})
		return
	}

	err := h.service.EnableTOTP(r.Context(), userID, req.Secret, req.Code, req.RecoveryCodes)
	if err != nil {
		switch err {
		case ErrInvalidCode:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid TOTP code"})
		case ErrAlreadyEnabled:
			writeJSON(w, http.StatusConflict, map[string]string{"error": "TOTP already enabled"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to enable TOTP"})
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "totp_enabled"})
}

// handleVerify verifies a TOTP code during login.
func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.UserID == "" || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id and code are required"})
		return
	}

	valid, err := h.service.Verify(r.Context(), req.UserID, req.Code)
	if err != nil {
		if err == ErrNotConfigured {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "TOTP not configured"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "verification failed"})
		return
	}

	if !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid TOTP code"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

// handleRecovery verifies a recovery code.
func (h *Handler) handleRecovery(w http.ResponseWriter, r *http.Request) {
	var req recoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.UserID == "" || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id and code are required"})
		return
	}

	valid, err := h.service.VerifyRecoveryCode(r.Context(), req.UserID, req.Code)
	if err != nil {
		if err == ErrNotConfigured {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "TOTP not configured"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "recovery verification failed"})
		return
	}

	if !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid recovery code"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
