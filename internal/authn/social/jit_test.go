package social

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/internal/storage/sqlite"
)

// mockJITProvisioner records ProvisionUser calls.
type mockJITProvisioner struct {
	called    bool
	userID    string
	source    string
	returnOrg *storage.Organization
}

func (m *mockJITProvisioner) ProvisionUser(_ context.Context, user *storage.User, source string) (*storage.Organization, error) {
	m.called = true
	m.userID = user.ID
	m.source = source
	return m.returnOrg, nil
}

func TestFindOrCreateUser_JITCalledOnNewUser(t *testing.T) {
	store, err := sqlite.New(config.DatabaseConfig{Driver: "sqlite", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cfg := map[string]config.SocialProvider{
		"google": {ClientID: "gid", ClientSecret: "gsecret"},
	}
	svc := NewService(cfg, store)

	mockOrg := &storage.Organization{
		ID:   "org_test",
		Slug: "test-org",
		Name: "Test Org",
	}
	jit := &mockJITProvisioner{returnOrg: mockOrg}
	svc.SetJITProvisioner(jit)

	su := &SocialUser{
		Provider:   "google",
		ProviderID: "goog-jit-1",
		Email:      "jituser@test.com",
		Name:       "JIT User",
	}

	user, isNew, err := svc.FindOrCreateUser(context.Background(), su)
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}
	if !isNew {
		t.Error("expected isNew=true")
	}
	if !jit.called {
		t.Fatal("expected JIT provisioner to be called")
	}
	if jit.userID != user.ID {
		t.Errorf("JIT called with userID=%q, want %q", jit.userID, user.ID)
	}
	if jit.source != "social:google" {
		t.Errorf("JIT source=%q, want social:google", jit.source)
	}
}

func TestFindOrCreateUser_JITNotCalledForExistingUser(t *testing.T) {
	store, err := sqlite.New(config.DatabaseConfig{Driver: "sqlite", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Pre-create user
	now := time.Now().UTC()
	_ = store.CreateUser(context.Background(), &storage.User{
		ID:        "existing-jit",
		Email:     "existing-jit@test.com",
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: now,
		UpdatedAt: now,
	})

	cfg := map[string]config.SocialProvider{
		"google": {ClientID: "gid", ClientSecret: "gsecret"},
	}
	svc := NewService(cfg, store)

	jit := &mockJITProvisioner{}
	svc.SetJITProvisioner(jit)

	su := &SocialUser{
		Provider:   "google",
		ProviderID: "goog-existing",
		Email:      "existing-jit@test.com",
		Name:       "Existing JIT User",
	}

	_, isNew, err := svc.FindOrCreateUser(context.Background(), su)
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}
	if isNew {
		t.Error("expected isNew=false for existing user")
	}
	if jit.called {
		t.Error("JIT provisioner should NOT be called for existing users")
	}
}
