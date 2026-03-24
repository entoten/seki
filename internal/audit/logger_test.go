package audit_test

import (
	"context"
	"testing"

	"github.com/Monet/seki/internal/audit"
	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/sqlite"
)

func newTestLogger(t *testing.T) (*audit.Logger, storage.Storage) {
	t.Helper()
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	logger := audit.NewLogger(s, config.AuditConfig{Output: "stdout"})
	return logger, s
}

func TestLogAuthEvent(t *testing.T) {
	logger, s := newTestLogger(t)
	ctx := context.Background()

	err := logger.LogAuth(ctx, audit.EventUserLogin, "user-1", "1.2.3.4", "TestAgent", nil)
	if err != nil {
		t.Fatalf("log auth: %v", err)
	}

	entries, _, err := s.ListAuditLogs(ctx, storage.AuditListOptions{Action: audit.EventUserLogin})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if entries[0].ActorID != "user-1" {
		t.Fatalf("want actor user-1, got %s", entries[0].ActorID)
	}
}

func TestLogAdminEvent(t *testing.T) {
	logger, s := newTestLogger(t)
	ctx := context.Background()

	err := logger.LogAdmin(ctx, "user.created", "admin-1", "user", "user-42", map[string]interface{}{"email": "a@b.com"})
	if err != nil {
		t.Fatalf("log admin: %v", err)
	}

	entries, _, err := s.ListAuditLogs(ctx, storage.AuditListOptions{ActorID: "admin-1"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1, got %d", len(entries))
	}
	if entries[0].ResourceID != "user-42" {
		t.Fatalf("want resource_id user-42, got %s", entries[0].ResourceID)
	}
}

func TestLogWithFilters(t *testing.T) {
	logger, s := newTestLogger(t)
	ctx := context.Background()

	_ = logger.LogAuth(ctx, audit.EventUserLogin, "user-1", "", "", nil)
	_ = logger.LogAuth(ctx, audit.EventUserLoginFailed, "user-2", "", "", nil)
	_ = logger.LogAuth(ctx, audit.EventUserLogin, "user-3", "", "", nil)

	entries, _, err := s.ListAuditLogs(ctx, storage.AuditListOptions{Action: audit.EventUserLogin})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 login entries, got %d", len(entries))
	}
}
