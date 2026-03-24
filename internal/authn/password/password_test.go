package password

import (
	"context"
	"testing"
	"time"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
	"github.com/Monet/seki/internal/storage/sqlite"
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

	svc := NewService(store)

	return svc, store, user
}

func TestRegisterValidPassword(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	err := svc.Register(ctx, user.ID, "securepassword123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func TestRegisterShortPassword(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	err := svc.Register(ctx, user.ID, "short")
	if err != ErrPasswordTooShort {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}
}

func TestVerifyCorrectPassword(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	password := "securepassword123"
	if err := svc.Register(ctx, user.ID, password); err != nil {
		t.Fatalf("Register: %v", err)
	}

	err := svc.Verify(ctx, user.ID, password)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	if err := svc.Register(ctx, user.ID, "securepassword123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	err := svc.Verify(ctx, user.ID, "wrongpassword")
	if err != ErrInvalidPassword {
		t.Fatalf("expected ErrInvalidPassword, got %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	oldPassword := "securepassword123"
	newPassword := "newsecurepassword456"

	if err := svc.Register(ctx, user.ID, oldPassword); err != nil {
		t.Fatalf("Register: %v", err)
	}

	err := svc.ChangePassword(ctx, user.ID, oldPassword, newPassword)
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Old password should no longer work.
	err = svc.Verify(ctx, user.ID, oldPassword)
	if err != ErrInvalidPassword {
		t.Fatalf("expected ErrInvalidPassword for old password, got %v", err)
	}

	// New password should work.
	err = svc.Verify(ctx, user.ID, newPassword)
	if err != nil {
		t.Fatalf("Verify new password: %v", err)
	}
}

func TestRemovePassword(t *testing.T) {
	svc, _, user := setupTest(t)
	ctx := context.Background()

	if err := svc.Register(ctx, user.ID, "securepassword123"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	err := svc.RemovePassword(ctx, user.ID)
	if err != nil {
		t.Fatalf("RemovePassword: %v", err)
	}

	// Verify should now fail with ErrNotConfigured.
	err = svc.Verify(ctx, user.ID, "securepassword123")
	if err != ErrNotConfigured {
		t.Fatalf("expected ErrNotConfigured after remove, got %v", err)
	}
}
