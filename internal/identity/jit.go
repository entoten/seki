package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
	"github.com/Monet/seki/internal/webhook"
)

// JITService provides Just-In-Time user provisioning.
// When a user signs in via social login for the first time, JIT provisioning
// automatically matches them to an organization based on their email domain
// and adds them as a member with a default role.
type JITService struct {
	store   storage.Storage
	emitter *webhook.Emitter
	cfg     config.JITConfig
}

// NewJITService creates a new JIT provisioning service.
func NewJITService(store storage.Storage, emitter *webhook.Emitter, cfg config.JITConfig) *JITService {
	role := cfg.DefaultRole
	if role == "" {
		role = "member"
	}
	cfg.DefaultRole = role
	return &JITService{
		store:   store,
		emitter: emitter,
		cfg:     cfg,
	}
}

// ProvisionUser performs JIT provisioning for a newly created user.
// It matches the user's email domain to an organization and adds them as a member.
// Returns the matched organization (or nil if no match).
func (s *JITService) ProvisionUser(ctx context.Context, user *storage.User, source string) (*storage.Organization, error) {
	if !s.cfg.Enabled {
		return nil, nil
	}

	org, err := s.MatchOrgByDomain(ctx, user.Email)
	if err != nil || org == nil {
		// No matching org is not an error — user is created without org membership.
		return nil, nil //nolint:nilerr // intentional: unmatched domain is not a failure
	}

	member := &storage.OrgMember{
		OrgID:    org.ID,
		UserID:   user.ID,
		Role:     s.cfg.DefaultRole,
		JoinedAt: time.Now().UTC(),
	}
	if err := s.store.AddMember(ctx, member); err != nil {
		return nil, fmt.Errorf("jit: add member: %w", err)
	}

	// Emit webhook event.
	if s.emitter != nil {
		s.emitter.Emit(ctx, "user.jit_provisioned", map[string]interface{}{
			"user_id":      user.ID,
			"email":        user.Email,
			"display_name": user.DisplayName,
			"org_id":       org.ID,
			"org_slug":     org.Slug,
			"role":         s.cfg.DefaultRole,
			"source":       source,
		})
	}

	return org, nil
}

// MatchOrgByDomain extracts the domain from the email and finds an organization
// with a matching domain.
func (s *JITService) MatchOrgByDomain(ctx context.Context, email string) (*storage.Organization, error) {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return nil, fmt.Errorf("jit: invalid email %q", email)
	}
	domain := strings.ToLower(parts[1])

	org, err := s.store.GetOrgByDomain(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("jit: match org by domain: %w", err)
	}
	return org, nil
}
