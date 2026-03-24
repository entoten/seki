package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/storage"
)

// SeedOrgsFromConfig creates organizations and their roles from the YAML
// configuration if they do not already exist in the store. Existing orgs
// are skipped (not overwritten).
func SeedOrgsFromConfig(ctx context.Context, store storage.Storage, orgs []config.OrganizationConfig) error {
	for _, oc := range orgs {
		// Check if org already exists by slug.
		_, err := store.GetOrgBySlug(ctx, oc.Slug)
		if err == nil {
			// Org already exists, skip.
			continue
		}
		if !errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("seed orgs: check slug %q: %w", oc.Slug, err)
		}

		now := time.Now().UTC()
		org := &storage.Organization{
			ID:        fmt.Sprintf("org_%s", oc.Slug),
			Slug:      oc.Slug,
			Name:      oc.Name,
			Domains:   oc.Domains,
			Metadata:  json.RawMessage(`{}`),
			CreatedAt: now,
			UpdatedAt: now,
		}
		if org.Domains == nil {
			org.Domains = []string{}
		}

		if err := store.CreateOrg(ctx, org); err != nil {
			return fmt.Errorf("seed orgs: create %q: %w", oc.Slug, err)
		}

		// Seed roles for this org.
		for _, rc := range oc.Roles {
			role := &storage.Role{
				ID:          fmt.Sprintf("role_%s_%s", oc.Slug, rc.Name),
				OrgID:       org.ID,
				Name:        rc.Name,
				Permissions: rc.Permissions,
				CreatedAt:   now,
			}
			if role.Permissions == nil {
				role.Permissions = []string{}
			}
			if err := store.CreateRole(ctx, role); err != nil {
				return fmt.Errorf("seed orgs: create role %q in %q: %w", rc.Name, oc.Slug, err)
			}
		}
	}

	return nil
}
