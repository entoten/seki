package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/sqlite"
	"github.com/Monet/seki/internal/webhook"
)

func setupHandlerTest(t *testing.T) (*VerificationHandler, *VerificationService, storage.Storage) {
	t.Helper()
	store := newTestStore(t)
	emitter := webhook.NewEmitter(config.WebhooksConfig{})
	svc := NewVerificationService(store, emitter)
	handler := NewVerificationHandler(svc)
	return handler, svc, store
}

func TestHandler_RequestEmailVerification(t *testing.T) {
	h, _, store := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	createTestUser(t, store, "usr_vh_001", "vh@example.com")

	req := httptest.NewRequest(http.MethodPost, "/identity/verify-email/request", nil)
	req.Header.Set("X-User-ID", "usr_vh_001")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "verification_email_requested" {
		t.Errorf("status = %q", resp["status"])
	}
}

func TestHandler_RequestEmailVerification_NoAuth(t *testing.T) {
	h, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/identity/verify-email/request", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandler_VerifyEmail(t *testing.T) {
	h, svc, store := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	createTestUser(t, store, "usr_ve_001", "ve@example.com")
	token, err := svc.RequestEmailVerification(context.Background(), "usr_ve_001")
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"token": token})
	req := httptest.NewRequest(http.MethodPost, "/identity/verify-email/confirm", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_VerifyEmail_InvalidToken(t *testing.T) {
	h, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body, _ := json.Marshal(map[string]string{"token": "invalid-token"})
	req := httptest.NewRequest(http.MethodPost, "/identity/verify-email/confirm", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandler_VerifyEmail_MissingToken(t *testing.T) {
	h, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body, _ := json.Marshal(map[string]string{"token": ""})
	req := httptest.NewRequest(http.MethodPost, "/identity/verify-email/confirm", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandler_VerifyEmail_AlreadyUsed(t *testing.T) {
	h, svc, store := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	createTestUser(t, store, "usr_used_vh", "used_vh@example.com")
	token, _ := svc.RequestEmailVerification(context.Background(), "usr_used_vh")

	// Use the token.
	_ = svc.VerifyEmail(context.Background(), token)

	// Try again via handler.
	body, _ := json.Marshal(map[string]string{"token": token})
	req := httptest.NewRequest(http.MethodPost, "/identity/verify-email/confirm", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandler_RequestPasswordReset(t *testing.T) {
	h, _, store := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	createTestUser(t, store, "usr_pr_vh", "pr_vh@example.com")

	body, _ := json.Marshal(map[string]string{"email": "pr_vh@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/identity/password-reset/request", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Unknown email should also return 200 (no user enumeration).
	body, _ = json.Marshal(map[string]string{"email": "unknown@example.com"})
	req = httptest.NewRequest(http.MethodPost, "/identity/password-reset/request", bytes.NewBuffer(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for unknown email, got %d", rec.Code)
	}
}

func TestHandler_RequestPasswordReset_MissingEmail(t *testing.T) {
	h, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body, _ := json.Marshal(map[string]string{"email": ""})
	req := httptest.NewRequest(http.MethodPost, "/identity/password-reset/request", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandler_ResetPassword(t *testing.T) {
	h, _, store := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	createTestUser(t, store, "usr_rp_vh", "rp_vh@example.com")

	// Create a password reset token directly.
	rawToken, tokenHash, _ := generateToken()
	now := time.Now().UTC()
	vt := &storage.VerificationToken{
		ID:        "vt_rp_vh",
		UserID:    "usr_rp_vh",
		Type:      TokenTypePasswordReset,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
	}
	if err := store.CreateVerificationToken(context.Background(), vt); err != nil {
		t.Fatalf("create token: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"token": rawToken, "new_password": "newSecurePassword123"})
	req := httptest.NewRequest(http.MethodPost, "/identity/password-reset/confirm", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_ResetPassword_MissingFields(t *testing.T) {
	h, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body, _ := json.Marshal(map[string]string{"token": "", "new_password": ""})
	req := httptest.NewRequest(http.MethodPost, "/identity/password-reset/confirm", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandler_ResetPassword_ShortPassword(t *testing.T) {
	h, _, store := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	createTestUser(t, store, "usr_short_vh", "short_vh@example.com")
	rawToken, tokenHash, _ := generateToken()
	now := time.Now().UTC()
	vt := &storage.VerificationToken{
		ID:        "vt_short_vh",
		UserID:    "usr_short_vh",
		Type:      TokenTypePasswordReset,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
	}
	_ = store.CreateVerificationToken(context.Background(), vt)

	body, _ := json.Marshal(map[string]string{"token": rawToken, "new_password": "short"})
	req := httptest.NewRequest(http.MethodPost, "/identity/password-reset/confirm", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandler_ResetPassword_ExpiredToken(t *testing.T) {
	h, _, store := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	createTestUser(t, store, "usr_exp_vh", "exp_vh@example.com")
	rawToken, tokenHash, _ := generateToken()
	now := time.Now().UTC()
	vt := &storage.VerificationToken{
		ID:        "vt_exp_vh",
		UserID:    "usr_exp_vh",
		Type:      TokenTypePasswordReset,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(-1 * time.Hour), // expired
		CreatedAt: now.Add(-2 * time.Hour),
	}
	_ = store.CreateVerificationToken(context.Background(), vt)

	body, _ := json.Marshal(map[string]string{"token": rawToken, "new_password": "newSecurePassword123"})
	req := httptest.NewRequest(http.MethodPost, "/identity/password-reset/confirm", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}
