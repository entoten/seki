package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/entoten/seki/internal/storage"
	_ "github.com/entoten/seki/internal/storage/sqlite" // register sqlite driver
)

func newTestStore(t *testing.T) storage.Storage {
	t.Helper()
	s, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ---------------------------------------------------------------------------
// User tests
// ---------------------------------------------------------------------------

func TestUserCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	user := &storage.User{
		ID:          "usr_001",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		Metadata:    json.RawMessage(`{"role":"admin"}`),
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
	}

	// Create
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Duplicate
	if err := s.CreateUser(ctx, user); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got: %v", err)
	}

	// Get by ID
	got, err := s.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if got.Email != user.Email {
		t.Fatalf("email mismatch: %s != %s", got.Email, user.Email)
	}
	if got.DisplayName != "Alice" {
		t.Fatalf("display name mismatch: %s", got.DisplayName)
	}

	// Get by email
	got, err = s.GetUserByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("get user by email: %v", err)
	}
	if got.ID != user.ID {
		t.Fatalf("id mismatch: %s != %s", got.ID, user.ID)
	}

	// Update
	got.DisplayName = "Alice Updated"
	got.Disabled = true
	if err := s.UpdateUser(ctx, got); err != nil {
		t.Fatalf("update user: %v", err)
	}
	got2, _ := s.GetUser(ctx, user.ID)
	if got2.DisplayName != "Alice Updated" {
		t.Fatalf("update failed: display_name=%s", got2.DisplayName)
	}
	if !got2.Disabled {
		t.Fatal("update failed: disabled should be true")
	}

	// Not found
	_, err = s.GetUser(ctx, "nonexistent")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	// Delete
	if err := s.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	_, err = s.GetUser(ctx, user.ID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}

	// Delete non-existent
	if err := s.DeleteUser(ctx, "nonexistent"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestUserListPagination(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Create 5 users
	for i := 0; i < 5; i++ {
		u := &storage.User{
			ID:        fmt.Sprintf("usr_%03d", i),
			Email:     fmt.Sprintf("user%d@example.com", i),
			Metadata:  json.RawMessage(`{}`),
			CreatedAt: time.Now().UTC().Truncate(time.Second),
		}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("create user %d: %v", i, err)
		}
	}

	// First page (limit 2)
	users, cursor, err := s.ListUsers(ctx, storage.ListOptions{Limit: 2})
	if err != nil {
		t.Fatalf("list users page 1: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if cursor == "" {
		t.Fatal("expected non-empty cursor")
	}

	// Second page
	users2, cursor2, err := s.ListUsers(ctx, storage.ListOptions{Limit: 2, Cursor: cursor})
	if err != nil {
		t.Fatalf("list users page 2: %v", err)
	}
	if len(users2) != 2 {
		t.Fatalf("expected 2 users on page 2, got %d", len(users2))
	}
	if users2[0].ID == users[0].ID {
		t.Fatal("page 2 should not overlap with page 1")
	}

	// Third page (last user)
	users3, cursor3, err := s.ListUsers(ctx, storage.ListOptions{Limit: 2, Cursor: cursor2})
	if err != nil {
		t.Fatalf("list users page 3: %v", err)
	}
	if len(users3) != 1 {
		t.Fatalf("expected 1 user on page 3, got %d", len(users3))
	}
	if cursor3 != "" {
		t.Fatalf("expected empty cursor on last page, got %q", cursor3)
	}
}

// ---------------------------------------------------------------------------
// Client tests
// ---------------------------------------------------------------------------

func TestClientCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	client := &storage.Client{
		ID:           "cli_001",
		Name:         "Test App",
		SecretHash:   "hashed_secret",
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "profile"},
		PKCERequired: true,
		Metadata:     json.RawMessage(`{}`),
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
	}

	// Create
	if err := s.CreateClient(ctx, client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Duplicate
	if err := s.CreateClient(ctx, client); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got: %v", err)
	}

	// Get
	got, err := s.GetClient(ctx, client.ID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if got.Name != "Test App" {
		t.Fatalf("name mismatch: %s", got.Name)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Fatalf("redirect_uris mismatch: %v", got.RedirectURIs)
	}
	if !got.PKCERequired {
		t.Fatal("pkce_required should be true")
	}

	// List
	clients, err := s.ListClients(ctx)
	if err != nil {
		t.Fatalf("list clients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}

	// Delete
	if err := s.DeleteClient(ctx, client.ID); err != nil {
		t.Fatalf("delete client: %v", err)
	}
	_, err = s.GetClient(ctx, client.ID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Session tests
// ---------------------------------------------------------------------------

func TestSessionCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Create a user first (FK constraint)
	user := &storage.User{
		ID:        "usr_sess",
		Email:     "sess@example.com",
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	session := &storage.Session{
		ID:                "ses_001",
		UserID:            user.ID,
		ClientID:          "cli_001",
		IPAddress:         "192.168.1.1",
		UserAgent:         "TestAgent/1.0",
		Metadata:          json.RawMessage(`{"device":"desktop"}`),
		CreatedAt:         time.Now().UTC().Truncate(time.Second),
		ExpiresAt:         time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second),
		LastActiveAt:      time.Now().UTC().Truncate(time.Second),
		AbsoluteExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second),
	}

	// Create
	if err := s.CreateSession(ctx, session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Get
	got, err := s.GetSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got.UserID != user.ID {
		t.Fatalf("user_id mismatch: %s", got.UserID)
	}
	if got.IPAddress != "192.168.1.1" {
		t.Fatalf("ip mismatch: %s", got.IPAddress)
	}

	// Not found
	_, err = s.GetSession(ctx, "nonexistent")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	// Delete
	if err := s.DeleteSession(ctx, session.ID); err != nil {
		t.Fatalf("delete session: %v", err)
	}
	_, err = s.GetSession(ctx, session.ID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	user := &storage.User{
		ID:        "usr_exp",
		Email:     "exp@example.com",
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Create an expired session
	expired := &storage.Session{
		ID:                "ses_expired",
		UserID:            user.ID,
		Metadata:          json.RawMessage(`{}`),
		CreatedAt:         now.Add(-2 * time.Hour),
		ExpiresAt:         now.Add(-1 * time.Hour),
		LastActiveAt:      now.Add(-2 * time.Hour),
		AbsoluteExpiresAt: now.Add(-1 * time.Hour),
	}
	// Create a valid session
	valid := &storage.Session{
		ID:                "ses_valid",
		UserID:            user.ID,
		Metadata:          json.RawMessage(`{}`),
		CreatedAt:         now,
		ExpiresAt:         now.Add(1 * time.Hour),
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, expired); err != nil {
		t.Fatalf("create expired session: %v", err)
	}
	if err := s.CreateSession(ctx, valid); err != nil {
		t.Fatalf("create valid session: %v", err)
	}

	// Delete expired
	count, err := s.DeleteExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("delete expired sessions: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 deleted, got %d", count)
	}

	// Valid session should still exist
	_, err = s.GetSession(ctx, valid.ID)
	if err != nil {
		t.Fatalf("valid session should still exist: %v", err)
	}

	// Expired session should be gone
	_, err = s.GetSession(ctx, expired.ID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired session should be deleted, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Audit log tests
// ---------------------------------------------------------------------------

func TestAuditLogCreateAndList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	entries := []*storage.AuditEntry{
		{
			ID:         "aud_001",
			ActorID:    "usr_001",
			Action:     "user.login",
			Resource:   "session",
			ResourceID: "ses_001",
			IPAddress:  "10.0.0.1",
			Metadata:   json.RawMessage(`{}`),
			CreatedAt:  time.Now().UTC().Truncate(time.Second),
		},
		{
			ID:         "aud_002",
			ActorID:    "usr_001",
			Action:     "user.update",
			Resource:   "user",
			ResourceID: "usr_001",
			Metadata:   json.RawMessage(`{"field":"email"}`),
			CreatedAt:  time.Now().UTC().Truncate(time.Second),
		},
		{
			ID:        "aud_003",
			ActorID:   "usr_002",
			Action:    "user.login",
			Resource:  "session",
			Metadata:  json.RawMessage(`{}`),
			CreatedAt: time.Now().UTC().Truncate(time.Second),
		},
	}

	for _, e := range entries {
		if err := s.CreateAuditLog(ctx, e); err != nil {
			t.Fatalf("create audit log %s: %v", e.ID, err)
		}
	}

	// List all
	all, cursor, err := s.ListAuditLogs(ctx, storage.AuditListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}
	if cursor != "" {
		t.Fatalf("expected empty cursor, got %q", cursor)
	}

	// Filter by actor
	byActor, _, err := s.ListAuditLogs(ctx, storage.AuditListOptions{ActorID: "usr_001", Limit: 10})
	if err != nil {
		t.Fatalf("list by actor: %v", err)
	}
	if len(byActor) != 2 {
		t.Fatalf("expected 2 entries for usr_001, got %d", len(byActor))
	}

	// Filter by action
	byAction, _, err := s.ListAuditLogs(ctx, storage.AuditListOptions{Action: "user.login", Limit: 10})
	if err != nil {
		t.Fatalf("list by action: %v", err)
	}
	if len(byAction) != 2 {
		t.Fatalf("expected 2 login entries, got %d", len(byAction))
	}

	// Pagination
	page1, cursor1, err := s.ListAuditLogs(ctx, storage.AuditListOptions{Limit: 2})
	if err != nil {
		t.Fatalf("list page 1: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("expected 2 entries on page 1, got %d", len(page1))
	}
	if cursor1 == "" {
		t.Fatal("expected non-empty cursor after page 1")
	}

	page2, cursor2, err := s.ListAuditLogs(ctx, storage.AuditListOptions{Limit: 2, Cursor: cursor1})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(page2) != 1 {
		t.Fatalf("expected 1 entry on page 2, got %d", len(page2))
	}
	if cursor2 != "" {
		t.Fatalf("expected empty cursor on last page, got %q", cursor2)
	}
}

func TestPing(t *testing.T) {
	s := newTestStore(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}
