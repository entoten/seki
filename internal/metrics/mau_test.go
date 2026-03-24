package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/storage"
	_ "github.com/entoten/seki/internal/storage/sqlite"
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

func createUser(t *testing.T, store storage.Storage, id string) {
	t.Helper()
	now := time.Now().UTC()
	err := store.CreateUser(context.Background(), &storage.User{
		ID:        id,
		Email:     id + "@example.com",
		CreatedAt: now,
		UpdatedAt: now,
		Metadata:  json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
}

func createLogin(t *testing.T, store storage.Storage, actorID string, at time.Time) {
	t.Helper()
	err := store.CreateAuditLog(context.Background(), &storage.AuditEntry{
		ID:        fmt.Sprintf("audit-%s-%d", actorID, at.UnixNano()),
		ActorID:   actorID,
		Action:    "user.login",
		Resource:  "session",
		CreatedAt: at,
		Metadata:  json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("create audit log: %v", err)
	}
}

func TestMAUTracker_GetMAU(t *testing.T) {
	store := newTestStore(t)
	tracker := NewMAUTracker(store)
	ctx := context.Background()
	now := time.Now().UTC()

	createUser(t, store, "mau-1")
	createUser(t, store, "mau-2")

	createLogin(t, store, "mau-1", now)
	createLogin(t, store, "mau-2", now)
	createLogin(t, store, "mau-1", now.Add(-time.Hour)) // duplicate

	count, err := tracker.GetMAU(ctx, now)
	if err != nil {
		t.Fatalf("GetMAU: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected MAU 2, got %d", count)
	}
}

func TestMAUTracker_GetMAU_Empty(t *testing.T) {
	store := newTestStore(t)
	tracker := NewMAUTracker(store)

	count, err := tracker.GetMAU(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("GetMAU: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected MAU 0, got %d", count)
	}
}

func TestMAUTracker_GetMAUByOrg(t *testing.T) {
	store := newTestStore(t)
	tracker := NewMAUTracker(store)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create org
	org := &storage.Organization{
		ID:        "org_mau_test",
		Slug:      "mau-test",
		Name:      "MAU Test Org",
		Domains:   []string{},
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.CreateOrg(ctx, org); err != nil {
		t.Fatalf("create org: %v", err)
	}

	createUser(t, store, "mau-org-1")
	createUser(t, store, "mau-org-2")

	// Only add first user to org
	err := store.AddMember(ctx, &storage.OrgMember{
		OrgID:    org.ID,
		UserID:   "mau-org-1",
		Role:     "member",
		JoinedAt: now,
	})
	if err != nil {
		t.Fatalf("add member: %v", err)
	}

	createLogin(t, store, "mau-org-1", now)
	createLogin(t, store, "mau-org-2", now)

	count, err := tracker.GetMAUByOrg(ctx, now, org.ID)
	if err != nil {
		t.Fatalf("GetMAUByOrg: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected org MAU 1, got %d", count)
	}
}

func TestMAUTracker_GetMAUHistory(t *testing.T) {
	store := newTestStore(t)
	tracker := NewMAUTracker(store)
	ctx := context.Background()
	now := time.Now().UTC()

	createUser(t, store, "hist-user")
	createLogin(t, store, "hist-user", now)

	history, err := tracker.GetMAUHistory(ctx, 3)
	if err != nil {
		t.Fatalf("GetMAUHistory: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("expected 3 months, got %d", len(history))
	}
	if history[0].MAU < 1 {
		t.Fatalf("expected current month MAU >= 1, got %d", history[0].MAU)
	}
	// Historical months should be 0
	if history[2].MAU != 0 {
		t.Fatalf("expected historical month MAU 0, got %d", history[2].MAU)
	}
}
