package oidc_test

import (
	"context"
	"testing"

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

func TestSeedClientsFromConfig_CreatesClients(t *testing.T) {
	store, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	clients := []config.ClientConfig{
		{
			ID:           "client-a",
			Name:         "Client A",
			Secret:       "my-secret",
			RedirectURIs: []string{"https://a.example.com/callback"},
			GrantTypes:   []string{"authorization_code"},
			Scopes:       []string{"openid", "profile"},
		},
		{
			ID:           "client-b",
			Name:         "Client B",
			RedirectURIs: []string{"https://b.example.com/callback"},
			GrantTypes:   []string{"authorization_code"},
			Scopes:       []string{"openid"},
		},
	}

	ctx := context.Background()
	if err := oidc.SeedClientsFromConfig(ctx, store, clients); err != nil {
		t.Fatalf("SeedClientsFromConfig: %v", err)
	}

	// Verify client-a was created with a hashed secret.
	a, err := store.GetClient(ctx, "client-a")
	if err != nil {
		t.Fatalf("GetClient(client-a): %v", err)
	}
	if a.Name != "Client A" {
		t.Errorf("expected name 'Client A', got %q", a.Name)
	}
	if a.SecretHash == "" {
		t.Error("expected client-a to have a hashed secret")
	}
	if !a.PKCERequired {
		t.Error("expected PKCERequired to default to true")
	}

	// Verify client-b was created without a secret.
	b, err := store.GetClient(ctx, "client-b")
	if err != nil {
		t.Fatalf("GetClient(client-b): %v", err)
	}
	if b.SecretHash != "" {
		t.Error("expected client-b to have no secret hash")
	}
}

func TestSeedClientsFromConfig_SkipsExisting(t *testing.T) {
	store, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ctx := context.Background()

	// Pre-create the client.
	err = store.CreateClient(ctx, &storage.Client{
		ID:           "existing-client",
		Name:         "Original Name",
		RedirectURIs: []string{"https://orig.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
		PKCERequired: true,
	})
	if err != nil {
		t.Fatalf("create existing client: %v", err)
	}

	// Seed with a config that has the same ID but different name.
	clients := []config.ClientConfig{
		{
			ID:   "existing-client",
			Name: "Updated Name",
		},
	}

	if err := oidc.SeedClientsFromConfig(ctx, store, clients); err != nil {
		t.Fatalf("SeedClientsFromConfig: %v", err)
	}

	// Verify the original was not overwritten.
	c, err := store.GetClient(ctx, "existing-client")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if c.Name != "Original Name" {
		t.Errorf("expected name 'Original Name', got %q (client was overwritten)", c.Name)
	}
}

func TestSeedClientsFromConfig_EmptyConfig(t *testing.T) {
	store, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ctx := context.Background()

	// Empty config should be a no-op.
	if err := oidc.SeedClientsFromConfig(ctx, store, nil); err != nil {
		t.Fatalf("SeedClientsFromConfig with nil: %v", err)
	}

	if err := oidc.SeedClientsFromConfig(ctx, store, []config.ClientConfig{}); err != nil {
		t.Fatalf("SeedClientsFromConfig with empty slice: %v", err)
	}
}
