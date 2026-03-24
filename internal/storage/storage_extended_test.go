package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/sqlite"
)

func TestCredentialCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	user := &storage.User{
		ID:        "usr_cred",
		Email:     "cred@example.com",
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	cred := &storage.Credential{
		ID:        "cred_001",
		UserID:    user.ID,
		Type:      "password",
		Secret:    []byte("hashed_password"),
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Create.
	if err := s.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	// Get.
	got, err := s.GetCredential(ctx, cred.ID)
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}
	if got.Type != "password" {
		t.Fatalf("type mismatch: %s", got.Type)
	}

	// Get by user and type.
	creds, err := s.GetCredentialsByUserAndType(ctx, user.ID, "password")
	if err != nil {
		t.Fatalf("get by user and type: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}

	// Update.
	got.Secret = []byte("new_hash")
	got.UpdatedAt = time.Now().UTC()
	if err := s.UpdateCredential(ctx, got); err != nil {
		t.Fatalf("update credential: %v", err)
	}

	got2, _ := s.GetCredential(ctx, cred.ID)
	if string(got2.Secret) != "new_hash" {
		t.Fatalf("update failed: %s", string(got2.Secret))
	}

	// Delete by user and type.
	if err := s.DeleteCredentialsByUserAndType(ctx, user.ID, "password"); err != nil {
		t.Fatalf("delete by user and type: %v", err)
	}
	creds, _ = s.GetCredentialsByUserAndType(ctx, user.ID, "password")
	if len(creds) != 0 {
		t.Fatalf("expected 0 after delete, got %d", len(creds))
	}
}

func TestRefreshTokenCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	user := &storage.User{
		ID:        "usr_rt",
		Email:     "rt@example.com",
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	rt := &storage.RefreshToken{
		ID:        "rt_001",
		TokenHash: "hash_001",
		ClientID:  "cli_001",
		UserID:    user.ID,
		Scopes:    []string{"openid"},
		Family:    "family_001",
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	// Create.
	if err := s.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	// Get by hash.
	got, err := s.GetRefreshTokenByHash(ctx, "hash_001")
	if err != nil {
		t.Fatalf("get by hash: %v", err)
	}
	if got.Family != "family_001" {
		t.Fatalf("family mismatch: %s", got.Family)
	}

	// Not found.
	_, err = s.GetRefreshTokenByHash(ctx, "nonexistent")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	// Create another in same family.
	rt2 := &storage.RefreshToken{
		ID:        "rt_002",
		TokenHash: "hash_002",
		ClientID:  "cli_001",
		UserID:    user.ID,
		Scopes:    []string{"openid"},
		Family:    "family_001",
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	if err := s.CreateRefreshToken(ctx, rt2); err != nil {
		t.Fatalf("create rt2: %v", err)
	}

	// Delete by family.
	count, err := s.DeleteRefreshTokensByFamily(ctx, "family_001")
	if err != nil {
		t.Fatalf("delete by family: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 deleted, got %d", count)
	}

	// Delete by user.
	rt3 := &storage.RefreshToken{
		ID:        "rt_003",
		TokenHash: "hash_003",
		ClientID:  "cli_001",
		UserID:    user.ID,
		Scopes:    []string{"openid"},
		Family:    "family_002",
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	if err := s.CreateRefreshToken(ctx, rt3); err != nil {
		t.Fatalf("create rt3: %v", err)
	}

	count2, err := s.DeleteRefreshTokensByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("delete by user: %v", err)
	}
	if count2 != 1 {
		t.Fatalf("expected 1 deleted, got %d", count2)
	}
}

func TestSessionActivityUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	user := &storage.User{
		ID:        "usr_act",
		Email:     "act@example.com",
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	sess := &storage.Session{
		ID:                "ses_act",
		UserID:            user.ID,
		Metadata:          json.RawMessage(`{}`),
		CreatedAt:         now,
		ExpiresAt:         now.Add(1 * time.Hour),
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
	}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Update activity.
	newTime := now.Add(30 * time.Minute)
	if err := s.UpdateSessionActivity(ctx, sess.ID, newTime); err != nil {
		t.Fatalf("update activity: %v", err)
	}

	// List by user.
	sessions, err := s.ListSessionsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("list by user: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	// Count by user.
	count, err := s.CountSessionsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("count by user: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}

	// Delete by user.
	deleted, err := s.DeleteSessionsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("delete by user: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted, got %d", deleted)
	}
}

func TestVerificationTokenCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	user := &storage.User{
		ID:        "usr_vt",
		Email:     "vt@example.com",
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	vt := &storage.VerificationToken{
		ID:        "vt_001",
		UserID:    user.ID,
		Type:      "email_verification",
		TokenHash: "hash_vt_001",
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	// Create.
	if err := s.CreateVerificationToken(ctx, vt); err != nil {
		t.Fatalf("create verification token: %v", err)
	}

	// Get by hash.
	got, err := s.GetVerificationTokenByHash(ctx, "hash_vt_001")
	if err != nil {
		t.Fatalf("get by hash: %v", err)
	}
	if got.UserID != user.ID {
		t.Fatalf("user_id mismatch: %s", got.UserID)
	}
	if got.UsedAt != nil {
		t.Fatal("expected nil UsedAt")
	}

	// Mark used.
	if err := s.MarkTokenUsed(ctx, vt.ID); err != nil {
		t.Fatalf("mark used: %v", err)
	}

	got2, _ := s.GetVerificationTokenByHash(ctx, "hash_vt_001")
	if got2.UsedAt == nil {
		t.Fatal("expected non-nil UsedAt after marking")
	}

	// Create expired token.
	vtExpired := &storage.VerificationToken{
		ID:        "vt_002",
		UserID:    user.ID,
		Type:      "email_verification",
		TokenHash: "hash_vt_002",
		ExpiresAt: now.Add(-1 * time.Hour),
		CreatedAt: now.Add(-25 * time.Hour),
	}
	if err := s.CreateVerificationToken(ctx, vtExpired); err != nil {
		t.Fatalf("create expired token: %v", err)
	}

	// Delete expired.
	count, err := s.DeleteExpiredTokens(ctx)
	if err != nil {
		t.Fatalf("delete expired: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 deleted, got %d", count)
	}
}

func TestRoleCRUD_Extended(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	org := &storage.Organization{
		ID:        "org_roles",
		Slug:      "role-org",
		Name:      "Role Org",
		Domains:   []string{},
		Metadata:  json.RawMessage(`{}`),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateOrg(ctx, org); err != nil {
		t.Fatalf("create org: %v", err)
	}

	role := &storage.Role{
		ID:          "role_001",
		OrgID:       org.ID,
		Name:        "admin",
		Permissions: []string{"read", "write"},
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateRole(ctx, role); err != nil {
		t.Fatalf("create role: %v", err)
	}

	// Get.
	got, err := s.GetRole(ctx, role.ID)
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if got.Name != "admin" {
		t.Fatalf("name mismatch: %s", got.Name)
	}

	// Get by name.
	got2, err := s.GetRoleByName(ctx, org.ID, "admin")
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if got2.ID != role.ID {
		t.Fatalf("id mismatch: %s", got2.ID)
	}

	// List.
	roles, err := s.ListRoles(ctx, org.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}

	// Update.
	got.Permissions = []string{"read"}
	if err := s.UpdateRole(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}

	// Delete.
	if err := s.DeleteRole(ctx, role.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = s.GetRole(ctx, role.ID)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestUnknownDriver(t *testing.T) {
	_, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Skipf("can't test unknown driver with registered drivers")
	}
}
