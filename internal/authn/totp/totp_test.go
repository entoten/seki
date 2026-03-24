package totp

import (
	"context"
	"testing"
	"time"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
	"github.com/Monet/seki/internal/storage/sqlite"
	"github.com/pquerna/otp/totp"
)

func setupTest(t *testing.T) (*Service, storage.Storage, *storage.User) {
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
		ID:        "user-001",
		Email:     "alice@example.com",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := config.TOTPConfig{
		Enabled: true,
		Issuer:  "SekiTest",
	}
	svc := NewService(cfg, store)

	return svc, store, user
}

func TestGenerateSecret(t *testing.T) {
	svc, _, user := setupTest(t)

	key, codes, err := svc.GenerateSecret(user)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if key.URL() == "" {
		t.Error("expected non-empty OTPAuth URL")
	}
	if key.Secret() == "" {
		t.Error("expected non-empty secret")
	}

	if len(codes) != recoveryCodeCount {
		t.Errorf("expected %d recovery codes, got %d", recoveryCodeCount, len(codes))
	}
	for i, code := range codes {
		if len(code) != recoveryCodeLen {
			t.Errorf("recovery code %d: expected length %d, got %d", i, recoveryCodeLen, len(code))
		}
	}
}

func TestEnableTOTPCorrectCode(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	key, codes, err := svc.GenerateSecret(user)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	// Generate a valid code from the secret.
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	err = svc.EnableTOTP(ctx, user.ID, key.Secret(), code, codes)
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
}

func TestEnableTOTPWrongCode(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	key, codes, err := svc.GenerateSecret(user)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	err = svc.EnableTOTP(ctx, user.ID, key.Secret(), "000000", codes)
	if err != ErrInvalidCode {
		t.Fatalf("expected ErrInvalidCode, got %v", err)
	}
}

func TestVerifyCorrectCode(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	key, codes, err := svc.GenerateSecret(user)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.EnableTOTP(ctx, user.ID, key.Secret(), code, codes); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	// Generate another valid code for verification.
	code2, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	valid, err := svc.Verify(ctx, user.ID, code2)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Error("expected valid verification")
	}
}

func TestVerifyWrongCode(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	key, codes, err := svc.GenerateSecret(user)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.EnableTOTP(ctx, user.ID, key.Secret(), code, codes); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	valid, err := svc.Verify(ctx, user.ID, "000000")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if valid {
		t.Error("expected invalid verification for wrong code")
	}
}

func TestRecoveryCodeWorksOnce(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	key, codes, err := svc.GenerateSecret(user)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.EnableTOTP(ctx, user.ID, key.Secret(), code, codes); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	// Use first recovery code.
	valid, err := svc.VerifyRecoveryCode(ctx, user.ID, codes[0])
	if err != nil {
		t.Fatalf("VerifyRecoveryCode: %v", err)
	}
	if !valid {
		t.Error("expected valid recovery code")
	}
}

func TestRecoveryCodeDoesNotWorkTwice(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	key, codes, err := svc.GenerateSecret(user)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.EnableTOTP(ctx, user.ID, key.Secret(), code, codes); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	// Use first recovery code.
	valid, err := svc.VerifyRecoveryCode(ctx, user.ID, codes[0])
	if err != nil {
		t.Fatalf("first VerifyRecoveryCode: %v", err)
	}
	if !valid {
		t.Fatal("expected first recovery code to be valid")
	}

	// Try the same code again - should fail.
	valid, err = svc.VerifyRecoveryCode(ctx, user.ID, codes[0])
	if err != nil {
		t.Fatalf("second VerifyRecoveryCode: %v", err)
	}
	if valid {
		t.Error("expected recovery code to be consumed and invalid on second use")
	}
}

func TestDisable(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	key, codes, err := svc.GenerateSecret(user)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.EnableTOTP(ctx, user.ID, key.Secret(), code, codes); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	// Disable TOTP.
	if err := svc.Disable(ctx, user.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	// Verify should now fail with ErrNotConfigured.
	_, err = svc.Verify(ctx, user.ID, "000000")
	if err != ErrNotConfigured {
		t.Fatalf("expected ErrNotConfigured after disable, got %v", err)
	}
}
