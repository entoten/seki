package totp

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
	"github.com/Monet/seki/internal/storage/sqlite"
	totpLib "github.com/pquerna/otp/totp"
)

func setupHandlerTest(t *testing.T) (*Handler, *Service, storage.Storage, *storage.User) {
	t.Helper()
	store, err := sqlite.New(config.DatabaseConfig{Driver: "sqlite", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	user := &storage.User{
		ID:        "user-totp-handler",
		Email:     "totphandler@example.com",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := config.TOTPConfig{Enabled: true, Issuer: "TestIssuer"}
	svc := NewService(cfg, store)
	handler := NewHandler(svc, store)
	return handler, svc, store, user
}

func TestHandler_SetupBegin(t *testing.T) {
	h, _, _, user := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/authn/totp/setup/begin", nil)
	req.Header.Set("X-User-ID", user.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["otpauth_uri"] == nil || resp["otpauth_uri"] == "" {
		t.Error("missing otpauth_uri")
	}
	if resp["secret"] == nil || resp["secret"] == "" {
		t.Error("missing secret")
	}
	if resp["recovery_codes"] == nil {
		t.Error("missing recovery_codes")
	}
}

func TestHandler_SetupBegin_NoAuth(t *testing.T) {
	h, _, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/authn/totp/setup/begin", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandler_SetupFinish_And_Verify(t *testing.T) {
	h, svc, _, user := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Generate secret.
	key, codes, err := svc.GenerateSecret(user)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	// Generate valid code.
	code, err := totpLib.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	// Setup finish.
	finishBody, _ := json.Marshal(map[string]interface{}{
		"code":           code,
		"secret":         key.Secret(),
		"recovery_codes": codes,
	})
	req := httptest.NewRequest(http.MethodPost, "/authn/totp/setup/finish", bytes.NewBuffer(finishBody))
	req.Header.Set("X-User-ID", user.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup/finish: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify with valid code.
	code2, _ := totpLib.GenerateCode(key.Secret(), time.Now())
	verifyBody, _ := json.Marshal(map[string]interface{}{
		"user_id": user.ID,
		"code":    code2,
	})
	req = httptest.NewRequest(http.MethodPost, "/authn/totp/verify", bytes.NewBuffer(verifyBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify with wrong code.
	wrongBody, _ := json.Marshal(map[string]interface{}{
		"user_id": user.ID,
		"code":    "000000",
	})
	req = httptest.NewRequest(http.MethodPost, "/authn/totp/verify", bytes.NewBuffer(wrongBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: expected 401, got %d", rec.Code)
	}

	// Recovery code.
	recoveryBody, _ := json.Marshal(map[string]interface{}{
		"user_id": user.ID,
		"code":    codes[0],
	})
	req = httptest.NewRequest(http.MethodPost, "/authn/totp/recovery", bytes.NewBuffer(recoveryBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_SetupFinish_NoAuth(t *testing.T) {
	h, _, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"code":"123456","secret":"ABCDEFGH"}`
	req := httptest.NewRequest(http.MethodPost, "/authn/totp/setup/finish", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandler_SetupFinish_MissingFields(t *testing.T) {
	h, _, _, user := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"code":"","secret":""}`
	req := httptest.NewRequest(http.MethodPost, "/authn/totp/setup/finish", bytes.NewBufferString(body))
	req.Header.Set("X-User-ID", user.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandler_Verify_MissingFields(t *testing.T) {
	h, _, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"user_id":"","code":""}`
	req := httptest.NewRequest(http.MethodPost, "/authn/totp/verify", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandler_Verify_NotConfigured(t *testing.T) {
	h, _, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"user_id":"user-totp-handler","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/authn/totp/verify", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (not configured), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_Recovery_MissingFields(t *testing.T) {
	h, _, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"user_id":"","code":""}`
	req := httptest.NewRequest(http.MethodPost, "/authn/totp/recovery", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandler_Recovery_NotConfigured(t *testing.T) {
	h, _, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"user_id":"user-totp-handler","code":"abc123"}`
	req := httptest.NewRequest(http.MethodPost, "/authn/totp/recovery", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (not configured), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_SetupFinish_AlreadyEnabled(t *testing.T) {
	h, svc, _, user := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Enable TOTP first.
	key, codes, _ := svc.GenerateSecret(user)
	code, _ := totpLib.GenerateCode(key.Secret(), time.Now())
	_ = svc.EnableTOTP(context.Background(), user.ID, key.Secret(), code, codes)

	// Try to enable again.
	code2, _ := totpLib.GenerateCode(key.Secret(), time.Now())
	finishBody, _ := json.Marshal(map[string]interface{}{
		"code":   code2,
		"secret": key.Secret(),
	})
	req := httptest.NewRequest(http.MethodPost, "/authn/totp/setup/finish", bytes.NewBuffer(finishBody))
	req.Header.Set("X-User-ID", user.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}
