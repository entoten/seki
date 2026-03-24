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

func newJITTestService(t *testing.T, enabled bool) (*JITService, storage.Storage) {
	t.Helper()
	store := newTestStore(t)
	emitter := webhook.NewEmitter(config.WebhooksConfig{})
	cfg := config.JITConfig{
		Enabled:     enabled,
		DefaultRole: "member",
	}
	svc := NewJITService(store, emitter, cfg)
	return svc, store
}

func createTestOrg(t *testing.T, store storage.Storage, slug string, domains []string) *storage.Organization {
	t.Helper()
	now := time.Now().UTC()
	org := &storage.Organization{
		ID:        "org_" + slug,
		Slug:      slug,
		Name:      "Org " + slug,
		Domains:   domains,
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.CreateOrg(context.Background(), org); err != nil {
		t.Fatalf("create org: %v", err)
	}
	return org
}

func TestJITProvisionUser_MatchesDomain(t *testing.T) {
	svc, store := newJITTestService(t, true)
	ctx := context.Background()

	// Create org with domain
	org := createTestOrg(t, store, "acme", []string{"acme.com"})

	// Create user
	user := createTestUser(t, store, "user-jit-1", "alice@acme.com")

	// Provision
	matchedOrg, err := svc.ProvisionUser(ctx, user, "social:google")
	if err != nil {
		t.Fatalf("provision user: %v", err)
	}
	if matchedOrg == nil {
		t.Fatal("expected org match, got nil")
	}
	if matchedOrg.ID != org.ID {
		t.Fatalf("expected org %s, got %s", org.ID, matchedOrg.ID)
	}

	// Verify membership
	member, err := store.GetMembership(ctx, org.ID, user.ID)
	if err != nil {
		t.Fatalf("get membership: %v", err)
	}
	if member.Role != "member" {
		t.Fatalf("expected role 'member', got %q", member.Role)
	}
}

func TestJITProvisionUser_NoDomainMatch(t *testing.T) {
	svc, store := newJITTestService(t, true)
	ctx := context.Background()

	// Create org with a different domain
	createTestOrg(t, store, "other-corp", []string{"other.com"})

	// Create user with non-matching email
	user := createTestUser(t, store, "user-jit-2", "bob@nope.com")

	// Provision — should return nil org without error
	matchedOrg, err := svc.ProvisionUser(ctx, user, "social:github")
	if err != nil {
		t.Fatalf("provision user: %v", err)
	}
	if matchedOrg != nil {
		t.Fatalf("expected no org match, got %s", matchedOrg.ID)
	}
}

func TestJITProvisionUser_Disabled(t *testing.T) {
	svc, store := newJITTestService(t, false)
	ctx := context.Background()

	createTestOrg(t, store, "disabled-org", []string{"disabled.com"})
	user := createTestUser(t, store, "user-jit-3", "charlie@disabled.com")

	matchedOrg, err := svc.ProvisionUser(ctx, user, "social:google")
	if err != nil {
		t.Fatalf("provision user: %v", err)
	}
	if matchedOrg != nil {
		t.Fatal("expected nil org when JIT disabled")
	}
}

func TestJITMatchOrgByDomain(t *testing.T) {
	svc, store := newJITTestService(t, true)
	ctx := context.Background()

	createTestOrg(t, store, "example-org", []string{"example.com", "example.org"})

	org, err := svc.MatchOrgByDomain(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("match org: %v", err)
	}
	if org.Slug != "example-org" {
		t.Fatalf("expected slug example-org, got %s", org.Slug)
	}

	// Also matches the second domain
	org, err = svc.MatchOrgByDomain(ctx, "user@example.org")
	if err != nil {
		t.Fatalf("match org second domain: %v", err)
	}
	if org.Slug != "example-org" {
		t.Fatalf("expected slug example-org, got %s", org.Slug)
	}

	// No match
	_, err = svc.MatchOrgByDomain(ctx, "user@unknown.com")
	if err == nil {
		t.Fatal("expected error for unknown domain")
	}
}
