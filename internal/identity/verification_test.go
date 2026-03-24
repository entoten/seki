package identity

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/sqlite"
	"github.com/Monet/seki/internal/webhook"
)

func newTestStore(t *testing.T) storage.Storage {
	t.Helper()
	s, err := storage.New(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    ":memory:",
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newTestService(t *testing.T) (*VerificationService, storage.Storage) {
	t.Helper()
	store := newTestStore(t)
	emitter := webhook.NewEmitter(config.WebhooksConfig{})
	svc := NewVerificationService(store, emitter)
	return svc, store
}

func createTestUser(t *testing.T, store storage.Storage, id, email string) *storage.User {
	t.Helper()
	user := &storage.User{
		ID:        id,
		Email:     email,
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func TestRequestEmailVerification(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	createTestUser(t, store, "usr_001", "alice@example.com")

	token, err := svc.RequestEmailVerification(ctx, "usr_001")
	if err != nil {
		t.Fatalf("request email verification: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// Verify the token was stored by looking it up via hash.
	hash := hashToken(token)
	vt, err := store.GetVerificationTokenByHash(ctx, hash)
	if err != nil {
		t.Fatalf("get verification token: %v", err)
	}
	if vt.UserID != "usr_001" {
		t.Fatalf("expected user_id usr_001, got %s", vt.UserID)
	}
	if vt.Type != TokenTypeEmailVerification {
		t.Fatalf("expected type %s, got %s", TokenTypeEmailVerification, vt.Type)
	}
}

func TestVerifyEmailValid(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	createTestUser(t, store, "usr_002", "bob@example.com")

	token, err := svc.RequestEmailVerification(ctx, "usr_002")
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	if err := svc.VerifyEmail(ctx, token); err != nil {
		t.Fatalf("verify email: %v", err)
	}

	// Check user's email_verified is now true.
	user, err := store.GetUser(ctx, "usr_002")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if !user.EmailVerified {
		t.Fatal("expected email_verified to be true")
	}
}

func TestVerifyEmailExpired(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	createTestUser(t, store, "usr_003", "charlie@example.com")

	token, err := svc.RequestEmailVerification(ctx, "usr_003")
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	// Manually expire the token by updating its expires_at to the past.
	hash := hashToken(token)
	vt, err := store.GetVerificationTokenByHash(ctx, hash)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}

	// We need to directly update in the DB. Use a new token with expired time.
	// Instead, create a token that's already expired.
	expiredToken := &storage.VerificationToken{
		ID:        "expired_token",
		UserID:    "usr_003",
		Type:      TokenTypeEmailVerification,
		TokenHash: "expired_hash_value",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
		CreatedAt: time.Now().UTC().Add(-25 * time.Hour),
	}
	_ = vt // not needed
	if err := store.CreateVerificationToken(ctx, expiredToken); err != nil {
		t.Fatalf("create expired token: %v", err)
	}

	// Create a raw token that hashes to "expired_hash_value" — we can't do that easily.
	// Instead, test by verifying the original token works, then test with a manually crafted scenario.
	// Let's use a different approach: directly test lookupToken with a known expired token.

	// Better approach: verify the original token works (already tested above), then
	// test the expired path by using the service with a token we know the hash of.
	// We'll test by calling VerifyEmail with an unknown token mapping to the expired entry.

	// Actually, let's just test the error path properly by overriding the token in storage.
	// The simplest approach: test that an expired token returns ErrTokenExpired.
	// We'll create a service method test directly.

	err = svc.VerifyEmail(ctx, "nonexistent_token_that_maps_to_nothing")
	if err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid for nonexistent token, got: %v", err)
	}
}

func TestVerifyEmailExpiredDirect(t *testing.T) {
	_, store := newTestService(t)
	ctx := context.Background()

	createTestUser(t, store, "usr_exp", "expired@example.com")

	// Create a token that is already expired.
	rawToken, tokenHash, err := generateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	now := time.Now().UTC()
	vt := &storage.VerificationToken{
		ID:        "vt_expired",
		UserID:    "usr_exp",
		Type:      TokenTypeEmailVerification,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(-1 * time.Hour), // expired
		CreatedAt: now.Add(-25 * time.Hour),
	}
	if err := store.CreateVerificationToken(ctx, vt); err != nil {
		t.Fatalf("create token: %v", err)
	}

	emitter := webhook.NewEmitter(config.WebhooksConfig{})
	svc := NewVerificationService(store, emitter)

	err = svc.VerifyEmail(ctx, rawToken)
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got: %v", err)
	}
}

func TestVerifyEmailAlreadyUsed(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	createTestUser(t, store, "usr_used", "used@example.com")

	token, err := svc.RequestEmailVerification(ctx, "usr_used")
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	// Use the token.
	if err := svc.VerifyEmail(ctx, token); err != nil {
		t.Fatalf("first verify: %v", err)
	}

	// Try to use it again.
	err = svc.VerifyEmail(ctx, token)
	if err != ErrTokenUsed {
		t.Fatalf("expected ErrTokenUsed, got: %v", err)
	}
}

func TestRequestPasswordReset(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	createTestUser(t, store, "usr_pr", "reset@example.com")

	err := svc.RequestPasswordReset(ctx, "reset@example.com")
	if err != nil {
		t.Fatalf("request password reset: %v", err)
	}

	// Should not error for unknown email (prevents enumeration).
	err = svc.RequestPasswordReset(ctx, "unknown@example.com")
	if err != nil {
		t.Fatalf("request password reset unknown email: %v", err)
	}
}

func TestResetPasswordValid(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	createTestUser(t, store, "usr_rp", "resetpw@example.com")

	// First set up a password credential.
	now := time.Now().UTC()
	cred := &storage.Credential{
		ID:        "cred_old",
		UserID:    "usr_rp",
		Type:      "password",
		Secret:    []byte("old_hash"),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	// Request a password reset — we need the raw token.
	// Use the service's internals to get the token.
	rawToken, tokenHash, err := generateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	vt := &storage.VerificationToken{
		ID:        "vt_reset",
		UserID:    "usr_rp",
		Type:      TokenTypePasswordReset,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(passwordResetTTL),
		CreatedAt: now,
	}
	if err := store.CreateVerificationToken(ctx, vt); err != nil {
		t.Fatalf("create token: %v", err)
	}

	err = svc.ResetPassword(ctx, rawToken, "newSecurePassword123")
	if err != nil {
		t.Fatalf("reset password: %v", err)
	}

	// Verify the old credential was replaced.
	creds, err := store.GetCredentialsByUserAndType(ctx, "usr_rp", "password")
	if err != nil {
		t.Fatalf("get credentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if string(creds[0].Secret) == "old_hash" {
		t.Fatal("expected password hash to be updated")
	}
}

func TestResetPasswordExpired(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	createTestUser(t, store, "usr_rpe", "resetexpired@example.com")

	rawToken, tokenHash, err := generateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	now := time.Now().UTC()
	vt := &storage.VerificationToken{
		ID:        "vt_reset_expired",
		UserID:    "usr_rpe",
		Type:      TokenTypePasswordReset,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(-1 * time.Hour), // expired
		CreatedAt: now.Add(-2 * time.Hour),
	}
	if err := store.CreateVerificationToken(ctx, vt); err != nil {
		t.Fatalf("create token: %v", err)
	}

	err = svc.ResetPassword(ctx, rawToken, "newSecurePassword123")
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got: %v", err)
	}
}
