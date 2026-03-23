package session_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Monet/seki/internal/session"
	"github.com/Monet/seki/internal/storage"

	_ "github.com/Monet/seki/internal/storage/sqlite"
)

func newTestManager(t *testing.T, cfg session.Config) (*session.Manager, storage.Storage) {
	t.Helper()
	store, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Create a test user (sessions require FK to users).
	now := time.Now().UTC()
	err = store.CreateUser(context.Background(), &storage.User{
		ID:        "user-1",
		Email:     "test@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	return session.NewManager(store, cfg), store
}

func TestCreateAndGet(t *testing.T) {
	mgr, _ := newTestManager(t, session.Config{})
	ctx := context.Background()

	sess, err := mgr.Create(ctx, "user-1", "", "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("session ID should not be empty")
	}
	if sess.UserID != "user-1" {
		t.Fatalf("want user-1, got %s", sess.UserID)
	}

	got, err := mgr.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UserID != "user-1" {
		t.Fatalf("get: want user-1, got %s", got.UserID)
	}
}

func TestIdleTimeout(t *testing.T) {
	mgr, _ := newTestManager(t, session.Config{
		IdleTimeout:     1 * time.Second,
		AbsoluteTimeout: 1 * time.Hour,
	})
	ctx := context.Background()

	sess, err := mgr.Create(ctx, "user-1", "", "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	time.Sleep(2100 * time.Millisecond)

	_, err = mgr.Get(ctx, sess.ID)
	if err != session.ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestAbsoluteTimeout(t *testing.T) {
	mgr, _ := newTestManager(t, session.Config{
		IdleTimeout:     1 * time.Hour,
		AbsoluteTimeout: 1 * time.Second,
	})
	ctx := context.Background()

	sess, err := mgr.Create(ctx, "user-1", "", "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	time.Sleep(2100 * time.Millisecond)

	_, err = mgr.Get(ctx, sess.ID)
	if err != session.ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestRotate(t *testing.T) {
	mgr, _ := newTestManager(t, session.Config{})
	ctx := context.Background()

	old, err := mgr.Create(ctx, "user-1", "", "1.2.3.4", "TestAgent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	newSess, err := mgr.Rotate(ctx, old.ID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newSess.ID == old.ID {
		t.Fatal("new session should have different ID")
	}
	if newSess.UserID != old.UserID {
		t.Fatal("rotated session should preserve user ID")
	}

	// Old session should be gone.
	_, err = mgr.Get(ctx, old.ID)
	if err == nil {
		t.Fatal("old session should be deleted after rotate")
	}
}

func TestDeleteByUserID(t *testing.T) {
	mgr, _ := newTestManager(t, session.Config{})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, err := mgr.Create(ctx, "user-1", "", "1.2.3.4", "TestAgent")
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	n, err := mgr.DeleteByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("delete by user: %v", err)
	}
	if n != 3 {
		t.Fatalf("want 3 deleted, got %d", n)
	}
}

func TestCleanup(t *testing.T) {
	// Use 2s timeout because SQLite stores timestamps at second precision (RFC3339).
	mgr, _ := newTestManager(t, session.Config{
		IdleTimeout:     1 * time.Second,
		AbsoluteTimeout: 1 * time.Second,
	})
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, err := mgr.Create(ctx, "user-1", "", "1.2.3.4", "TestAgent")
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	time.Sleep(2100 * time.Millisecond)

	n, err := mgr.Cleanup(ctx)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n != 5 {
		t.Fatalf("want 5 cleaned, got %d", n)
	}
}

func TestGetNonExistent(t *testing.T) {
	mgr, _ := newTestManager(t, session.Config{})
	ctx := context.Background()

	_, err := mgr.Get(ctx, "does-not-exist")
	if err == nil {
		t.Fatal("expected error for non-existent session")
	}
}

func TestCookieHelpers(t *testing.T) {
	mgr, _ := newTestManager(t, session.Config{CookieName: "test_sess"})
	ctx := context.Background()

	sess, _ := mgr.Create(ctx, "user-1", "", "1.2.3.4", "TestAgent")

	// SetCookie
	w := httptest.NewRecorder()
	mgr.SetCookie(w, sess)
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected cookie to be set")
	}
	if cookies[0].Name != "test_sess" {
		t.Fatalf("want cookie name test_sess, got %s", cookies[0].Name)
	}
	if !cookies[0].HttpOnly {
		t.Fatal("cookie should be HttpOnly")
	}

	// GetSessionID
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])
	id, err := mgr.GetSessionID(req)
	if err != nil {
		t.Fatalf("get session id: %v", err)
	}
	if id != sess.ID {
		t.Fatalf("want %s, got %s", sess.ID, id)
	}

	// ClearCookie
	w2 := httptest.NewRecorder()
	mgr.ClearCookie(w2)
	cleared := w2.Result().Cookies()
	if len(cleared) == 0 || cleared[0].MaxAge != -1 {
		t.Fatal("clear cookie should set MaxAge=-1")
	}
}
