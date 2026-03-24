package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/entoten/seki/internal/storage"
)

func TestOrgCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	org := &storage.Organization{
		ID:        "org_acme",
		Slug:      "acme",
		Name:      "Acme Corp",
		Domains:   []string{"acme.com"},
		Metadata:  json.RawMessage(`{"plan":"enterprise"}`),
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Create
	if err := s.CreateOrg(ctx, org); err != nil {
		t.Fatalf("create org: %v", err)
	}

	// Duplicate slug returns ErrAlreadyExists
	dup := &storage.Organization{
		ID:        "org_acme2",
		Slug:      "acme",
		Name:      "Acme Dup",
		Domains:   []string{},
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.CreateOrg(ctx, dup); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for dup slug, got: %v", err)
	}

	// Get by ID
	got, err := s.GetOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("get org by id: %v", err)
	}
	if got.Slug != "acme" || got.Name != "Acme Corp" {
		t.Fatalf("org mismatch: slug=%s name=%s", got.Slug, got.Name)
	}
	if len(got.Domains) != 1 || got.Domains[0] != "acme.com" {
		t.Fatalf("domains mismatch: %v", got.Domains)
	}

	// Get by slug
	got2, err := s.GetOrgBySlug(ctx, "acme")
	if err != nil {
		t.Fatalf("get org by slug: %v", err)
	}
	if got2.ID != org.ID {
		t.Fatalf("id mismatch: %s != %s", got2.ID, org.ID)
	}

	// Update
	got.Name = "Acme Corporation"
	got.Domains = []string{"acme.com", "acme.org"}
	if err := s.UpdateOrg(ctx, got); err != nil {
		t.Fatalf("update org: %v", err)
	}
	got3, _ := s.GetOrg(ctx, org.ID)
	if got3.Name != "Acme Corporation" {
		t.Fatalf("update failed: name=%s", got3.Name)
	}
	if len(got3.Domains) != 2 {
		t.Fatalf("update domains failed: %v", got3.Domains)
	}

	// Not found
	_, err = s.GetOrg(ctx, "nonexistent")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	// List
	orgs, cursor, err := s.ListOrgs(ctx, storage.ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("list orgs: %v", err)
	}
	if len(orgs) != 1 {
		t.Fatalf("expected 1 org, got %d", len(orgs))
	}
	if cursor != "" {
		t.Fatalf("expected empty cursor, got %q", cursor)
	}

	// Delete
	if err := s.DeleteOrg(ctx, org.ID); err != nil {
		t.Fatalf("delete org: %v", err)
	}
	_, err = s.GetOrg(ctx, org.ID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}

func TestMemberManagement(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// Create a user and an org first.
	user := &storage.User{
		ID:        "usr_member_test",
		Email:     "member@example.com",
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: now,
	}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	org := &storage.Organization{
		ID:        "org_member_test",
		Slug:      "member-test",
		Name:      "Member Test Org",
		Domains:   []string{},
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.CreateOrg(ctx, org); err != nil {
		t.Fatalf("create org: %v", err)
	}

	// Add member
	member := &storage.OrgMember{
		OrgID:    org.ID,
		UserID:   user.ID,
		Role:     "admin",
		JoinedAt: now,
	}
	if err := s.AddMember(ctx, member); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// Duplicate add returns ErrAlreadyExists
	if err := s.AddMember(ctx, member); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got: %v", err)
	}

	// Get membership
	got, err := s.GetMembership(ctx, org.ID, user.ID)
	if err != nil {
		t.Fatalf("get membership: %v", err)
	}
	if got.Role != "admin" {
		t.Fatalf("role mismatch: %s", got.Role)
	}

	// List members
	members, err := s.ListMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}

	// Update member role
	if err := s.UpdateMemberRole(ctx, org.ID, user.ID, "viewer"); err != nil {
		t.Fatalf("update member role: %v", err)
	}
	got2, _ := s.GetMembership(ctx, org.ID, user.ID)
	if got2.Role != "viewer" {
		t.Fatalf("role update failed: %s", got2.Role)
	}

	// Remove member
	if err := s.RemoveMember(ctx, org.ID, user.ID); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	_, err = s.GetMembership(ctx, org.ID, user.ID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after remove, got: %v", err)
	}

	// Remove non-existent
	if err := s.RemoveMember(ctx, org.ID, "nonexistent"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestRoleCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	org := &storage.Organization{
		ID:        "org_role_test",
		Slug:      "role-test",
		Name:      "Role Test Org",
		Domains:   []string{},
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.CreateOrg(ctx, org); err != nil {
		t.Fatalf("create org: %v", err)
	}

	role := &storage.Role{
		ID:          "role_admin",
		OrgID:       org.ID,
		Name:        "admin",
		Permissions: []string{"read", "write", "delete"},
		CreatedAt:   now,
	}

	// Create
	if err := s.CreateRole(ctx, role); err != nil {
		t.Fatalf("create role: %v", err)
	}

	// Duplicate name in same org
	dup := &storage.Role{
		ID:          "role_admin_dup",
		OrgID:       org.ID,
		Name:        "admin",
		Permissions: []string{},
		CreatedAt:   now,
	}
	if err := s.CreateRole(ctx, dup); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got: %v", err)
	}

	// Get by ID
	got, err := s.GetRole(ctx, role.ID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if got.Name != "admin" {
		t.Fatalf("name mismatch: %s", got.Name)
	}
	if len(got.Permissions) != 3 {
		t.Fatalf("permissions mismatch: %v", got.Permissions)
	}

	// Get by name
	got2, err := s.GetRoleByName(ctx, org.ID, "admin")
	if err != nil {
		t.Fatalf("get role by name: %v", err)
	}
	if got2.ID != role.ID {
		t.Fatalf("id mismatch: %s != %s", got2.ID, role.ID)
	}

	// List roles
	roles, err := s.ListRoles(ctx, org.ID)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}

	// Update permissions
	got.Permissions = []string{"read"}
	if err := s.UpdateRole(ctx, got); err != nil {
		t.Fatalf("update role: %v", err)
	}
	got3, _ := s.GetRole(ctx, role.ID)
	if len(got3.Permissions) != 1 || got3.Permissions[0] != "read" {
		t.Fatalf("update failed: permissions=%v", got3.Permissions)
	}

	// Delete
	if err := s.DeleteRole(ctx, role.ID); err != nil {
		t.Fatalf("delete role: %v", err)
	}
	_, err = s.GetRole(ctx, role.ID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}

func TestSlugUniqueness(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	org1 := &storage.Organization{
		ID:        "org_unique1",
		Slug:      "unique-slug",
		Name:      "Org 1",
		Domains:   []string{},
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.CreateOrg(ctx, org1); err != nil {
		t.Fatalf("create org1: %v", err)
	}

	org2 := &storage.Organization{
		ID:        "org_unique2",
		Slug:      "unique-slug",
		Name:      "Org 2",
		Domains:   []string{},
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.CreateOrg(ctx, org2); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for duplicate slug, got: %v", err)
	}
}
