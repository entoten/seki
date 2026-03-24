package pat_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/entoten/seki/internal/authn/pat"
	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

func setupStore(t *testing.T) storage.Storage {
	t.Helper()
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	// Create a test user.
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	err = s.CreateUser(ctx, &storage.User{
		ID:        "user-1",
		Email:     "alice@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return s
}

func TestGenerateAndValidateRoundTrip(t *testing.T) {
	s := setupStore(t)
	svc := pat.NewService(s)
	ctx := context.Background()

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	token, p, err := svc.Generate(ctx, "user-1", "my-token", []string{"read", "write"}, expiresAt)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if !strings.HasPrefix(token, pat.Prefix) {
		t.Fatalf("expected prefix %q, got %q", pat.Prefix, token[:len(pat.Prefix)])
	}
	if p.ID == "" {
		t.Fatal("expected non-empty PAT ID")
	}
	if p.UserID != "user-1" {
		t.Fatalf("expected user-1, got %s", p.UserID)
	}
	if p.Name != "my-token" {
		t.Fatalf("expected my-token, got %s", p.Name)
	}

	// Validate.
	validated, err := svc.Validate(ctx, token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if validated.ID != p.ID {
		t.Fatalf("ID mismatch: %s vs %s", validated.ID, p.ID)
	}
	if validated.LastUsedAt == nil {
		t.Fatal("expected last_used_at to be set after validation")
	}
}

func TestPrefixFormat(t *testing.T) {
	s := setupStore(t)
	svc := pat.NewService(s)
	ctx := context.Background()

	expiresAt := time.Now().UTC().Add(time.Hour)
	token, _, err := svc.Generate(ctx, "user-1", "prefix-test", nil, expiresAt)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if !strings.HasPrefix(token, "seki_pat_") {
		t.Fatalf("token should start with seki_pat_, got: %s", token)
	}

	// The part after the prefix should be base64url encoded (no padding).
	body := strings.TrimPrefix(token, "seki_pat_")
	if len(body) == 0 {
		t.Fatal("token body is empty")
	}
	// 32 bytes base64url = 43 chars.
	if len(body) != 43 {
		t.Fatalf("expected 43 chars for 32 bytes base64url, got %d", len(body))
	}
}

func TestExpiredPATRejected(t *testing.T) {
	s := setupStore(t)
	svc := pat.NewService(s)
	ctx := context.Background()

	// Create a token that already expired.
	expiresAt := time.Now().UTC().Add(-1 * time.Hour)
	token, _, err := svc.Generate(ctx, "user-1", "expired-token", nil, expiresAt)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	_, err = svc.Validate(ctx, token)
	if err != pat.ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestRevokedPATRejected(t *testing.T) {
	s := setupStore(t)
	svc := pat.NewService(s)
	ctx := context.Background()

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	token, p, err := svc.Generate(ctx, "user-1", "revoked-token", nil, expiresAt)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Revoke.
	if err := svc.Revoke(ctx, p.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Validate should fail.
	_, err = svc.Validate(ctx, token)
	if err != pat.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestLastUsedTracking(t *testing.T) {
	s := setupStore(t)
	svc := pat.NewService(s)
	ctx := context.Background()

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	token, p, err := svc.Generate(ctx, "user-1", "tracking-token", nil, expiresAt)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Initially, last_used_at should be nil.
	if p.LastUsedAt != nil {
		t.Fatal("expected nil last_used_at on creation")
	}

	// Validate to trigger last_used_at update.
	validated, err := svc.Validate(ctx, token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if validated.LastUsedAt == nil {
		t.Fatal("expected last_used_at to be set")
	}

	// List should also reflect the update.
	pats, err := s.ListPATsByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, pt := range pats {
		if pt.ID == p.ID && pt.LastUsedAt != nil {
			found = true
		}
	}
	if !found {
		t.Fatal("last_used_at not persisted")
	}
}

func TestInvalidTokenFormat(t *testing.T) {
	s := setupStore(t)
	svc := pat.NewService(s)
	ctx := context.Background()

	_, err := svc.Validate(ctx, "not-a-valid-token")
	if err != pat.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestListPATsByUser(t *testing.T) {
	s := setupStore(t)
	svc := pat.NewService(s)
	ctx := context.Background()

	expiresAt := time.Now().UTC().Add(24 * time.Hour)

	// Create multiple tokens.
	_, _, err := svc.Generate(ctx, "user-1", "token-1", []string{"read"}, expiresAt)
	if err != nil {
		t.Fatalf("generate 1: %v", err)
	}
	_, _, err = svc.Generate(ctx, "user-1", "token-2", []string{"write"}, expiresAt)
	if err != nil {
		t.Fatalf("generate 2: %v", err)
	}

	pats, err := s.ListPATsByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pats) != 2 {
		t.Fatalf("expected 2 PATs, got %d", len(pats))
	}
}
