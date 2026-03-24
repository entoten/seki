package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/storage"
)

// SeedClientsFromConfig creates clients from the YAML configuration if they
// do not already exist in the store. Existing clients are skipped (not
// overwritten). If a client config includes a Secret, it is hashed with
// bcrypt before storage.
func SeedClientsFromConfig(ctx context.Context, store storage.ClientStore, clients []config.ClientConfig) error {
	hasher := crypto.NewBcryptHasher(0) // default cost

	for _, cc := range clients {
		// Check if client already exists.
		_, err := store.GetClient(ctx, cc.ID)
		if err == nil {
			// Client already exists, skip.
			continue
		}
		if !errors.Is(err, storage.ErrNotFound) {
			return err
		}

		now := time.Now().UTC()

		client := &storage.Client{
			ID:           cc.ID,
			Name:         cc.Name,
			RedirectURIs: cc.RedirectURIs,
			GrantTypes:   cc.GrantTypes,
			Scopes:       cc.Scopes,
			PKCERequired: cc.PKCERequired,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		// If no PKCE preference was explicitly set and the value is the
		// zero value, default to true.
		if !cc.PKCERequired {
			client.PKCERequired = true
		}

		// Hash the secret if provided.
		if cc.Secret != "" {
			hash, err := hasher.Hash(cc.Secret)
			if err != nil {
				return err
			}
			client.SecretHash = hash
		}

		if err := store.CreateClient(ctx, client); err != nil {
			return err
		}
	}

	return nil
}
