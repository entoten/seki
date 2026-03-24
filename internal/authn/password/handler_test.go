package password

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
)

func setupHandlerTest(t *testing.T) (*Handler, storage.Storage, *storage.User) {
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
		ID:        "user-handler",
		Email:     "handler@example.com",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	svc := NewService(store)
	handler := NewHandler(svc, store)
	return handler, store, user
}

func TestHandlerRegister(t *testing.T) {
	h, _, user := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"password":"securepassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/authn/password/register", bytes.NewBufferString(body))
	req.Header.Set("X-User-ID", user.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerRegister_NoAuth(t *testing.T) {
	h, _, _ := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"password":"securepassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/authn/password/register", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandlerRegister_TooShort(t *testing.T) {
	h, _, user := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"password":"short"}`
	req := httptest.NewRequest(http.MethodPost, "/authn/password/register", bytes.NewBufferString(body))
	req.Header.Set("X-User-ID", user.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandlerRegister_EmptyPassword(t *testing.T) {
	h, _, user := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"password":""}`
	req := httptest.NewRequest(http.MethodPost, "/authn/password/register", bytes.NewBufferString(body))
	req.Header.Set("X-User-ID", user.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHandlerVerify(t *testing.T) {
	h, _, user := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Register first.
	regBody := `{"password":"securepassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/authn/password/register", bytes.NewBufferString(regBody))
	req.Header.Set("X-User-ID", user.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d", rec.Code)
	}

	// Verify correct.
	verifyBody := `{"email":"handler@example.com","password":"securepassword123"}`
	req = httptest.NewRequest(http.MethodPost, "/authn/password/verify", bytes.NewBufferString(verifyBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["user_id"] != user.ID {
		t.Errorf("user_id = %s, want %s", resp["user_id"], user.ID)
	}

	// Verify wrong password.
	wrongBody := `{"email":"handler@example.com","password":"wrongpassword"}`
	req = httptest.NewRequest(http.MethodPost, "/authn/password/verify", bytes.NewBufferString(wrongBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: expected 401, got %d", rec.Code)
	}

	// Verify unknown user.
	unknownBody := `{"email":"unknown@example.com","password":"anything"}`
	req = httptest.NewRequest(http.MethodPost, "/authn/password/verify", bytes.NewBufferString(unknownBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown user: expected 401, got %d", rec.Code)
	}

	// Verify missing fields.
	emptyBody := `{"email":"","password":""}`
	req = httptest.NewRequest(http.MethodPost, "/authn/password/verify", bytes.NewBufferString(emptyBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty fields: expected 400, got %d", rec.Code)
	}
}

func TestHandlerChange(t *testing.T) {
	h, _, user := setupHandlerTest(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Register first.
	regBody := `{"password":"oldpassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/authn/password/register", bytes.NewBufferString(regBody))
	req.Header.Set("X-User-ID", user.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Change password.
	changeBody := `{"old_password":"oldpassword123","new_password":"newpassword456"}`
	req = httptest.NewRequest(http.MethodPost, "/authn/password/change", bytes.NewBufferString(changeBody))
	req.Header.Set("X-User-ID", user.ID)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Change with wrong old password.
	badBody := `{"old_password":"wrongpassword","new_password":"newpassword789"}`
	req = httptest.NewRequest(http.MethodPost, "/authn/password/change", bytes.NewBufferString(badBody))
	req.Header.Set("X-User-ID", user.ID)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong old password: expected 401, got %d", rec.Code)
	}

	// Change without auth.
	req = httptest.NewRequest(http.MethodPost, "/authn/password/change", bytes.NewBufferString(changeBody))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: expected 401, got %d", rec.Code)
	}

	// Change with empty fields.
	emptyBody := `{"old_password":"","new_password":""}`
	req = httptest.NewRequest(http.MethodPost, "/authn/password/change", bytes.NewBufferString(emptyBody))
	req.Header.Set("X-User-ID", user.ID)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty: expected 400, got %d", rec.Code)
	}

	// Change with short new password.
	shortBody := `{"old_password":"newpassword456","new_password":"short"}`
	req = httptest.NewRequest(http.MethodPost, "/authn/password/change", bytes.NewBufferString(shortBody))
	req.Header.Set("X-User-ID", user.ID)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short new password: expected 400, got %d", rec.Code)
	}
}

func TestPasswordTooLong(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	longPw := string(make([]byte, 200))
	err := svc.Register(ctx, user.ID, longPw)
	if err != ErrPasswordTooLong {
		t.Fatalf("expected ErrPasswordTooLong, got %v", err)
	}
}

func TestChangePasswordNotConfigured(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	err := svc.ChangePassword(ctx, user.ID, "old", "newpassword123")
	if err != ErrNotConfigured {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestChangePasswordShortNew(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	if err := svc.Register(ctx, user.ID, "securepassword123"); err != nil {
		t.Fatalf("register: %v", err)
	}

	err := svc.ChangePassword(ctx, user.ID, "securepassword123", "short")
	if err != ErrPasswordTooShort {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}
}

func TestChangePasswordWrongOld(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	if err := svc.Register(ctx, user.ID, "securepassword123"); err != nil {
		t.Fatalf("register: %v", err)
	}

	err := svc.ChangePassword(ctx, user.ID, "wrongpassword", "newsecure123")
	if err != ErrInvalidPassword {
		t.Fatalf("expected ErrInvalidPassword, got %v", err)
	}
}
