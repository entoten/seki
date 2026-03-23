package passkey_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Monet/seki/internal/authn/passkey"
	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/sqlite" // register driver
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

func testUser(t *testing.T, s storage.Storage) *storage.User {
	t.Helper()
	user := &storage.User{
		ID:          "usr_passkey_test",
		Email:       "passkey@example.com",
		DisplayName: "Passkey Tester",
		Metadata:    json.RawMessage(`{}`),
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func testConfig() config.PasskeyConfig {
	return config.PasskeyConfig{
		Enabled: true,
		RPName:  "Seki Test",
		RPID:    "localhost",
	}
}

func TestNewService_ValidConfig(t *testing.T) {
	store := newTestStore(t)
	svc, err := passkey.NewService(testConfig(), store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestNewService_Disabled(t *testing.T) {
	store := newTestStore(t)
	cfg := testConfig()
	cfg.Enabled = false
	_, err := passkey.NewService(cfg, store)
	if err == nil {
		t.Fatal("expected error for disabled config")
	}
}

func TestNewService_MissingRPID(t *testing.T) {
	store := newTestStore(t)
	cfg := testConfig()
	cfg.RPID = ""
	_, err := passkey.NewService(cfg, store)
	if err == nil {
		t.Fatal("expected error for missing rp_id")
	}
}

func TestUserAdapter_WebAuthnInterface(t *testing.T) {
	user := &storage.User{
		ID:          "usr_001",
		Email:       "test@example.com",
		DisplayName: "Test User",
	}

	creds := []*storage.Credential{
		{
			ID:              "cred_001",
			UserID:          "usr_001",
			Type:            "passkey",
			CredentialID:    []byte("cred-id-bytes"),
			PublicKey:       []byte("pubkey-bytes"),
			AttestationType: "none",
			AAGUID:          []byte("aaguid-bytes-here"),
			SignCount:       5,
		},
	}

	adapter := passkey.NewUserAdapter(user, creds)

	// Check WebAuthnID is based on user ID, not email.
	if string(adapter.WebAuthnID()) != "usr_001" {
		t.Errorf("WebAuthnID = %q, want %q", string(adapter.WebAuthnID()), "usr_001")
	}

	// Check WebAuthnName is the email.
	if adapter.WebAuthnName() != "test@example.com" {
		t.Errorf("WebAuthnName = %q, want %q", adapter.WebAuthnName(), "test@example.com")
	}

	// Check WebAuthnDisplayName uses display name when set.
	if adapter.WebAuthnDisplayName() != "Test User" {
		t.Errorf("WebAuthnDisplayName = %q, want %q", adapter.WebAuthnDisplayName(), "Test User")
	}

	// Check credentials are converted.
	wanCreds := adapter.WebAuthnCredentials()
	if len(wanCreds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(wanCreds))
	}
	if string(wanCreds[0].ID) != "cred-id-bytes" {
		t.Errorf("credential ID = %q, want %q", string(wanCreds[0].ID), "cred-id-bytes")
	}
	if wanCreds[0].Authenticator.SignCount != 5 {
		t.Errorf("sign count = %d, want 5", wanCreds[0].Authenticator.SignCount)
	}
}

func TestUserAdapter_DisplayNameFallback(t *testing.T) {
	user := &storage.User{
		ID:          "usr_002",
		Email:       "fallback@example.com",
		DisplayName: "",
	}
	adapter := passkey.NewUserAdapter(user, nil)
	if adapter.WebAuthnDisplayName() != "fallback@example.com" {
		t.Errorf("expected email as display name fallback, got %q", adapter.WebAuthnDisplayName())
	}
}

func TestUserAdapter_ImplementsInterface(t *testing.T) {
	// This is a compile-time check that UserAdapter implements webauthn.User.
	var _ webauthn.User = passkey.NewUserAdapter(&storage.User{}, nil)
}

func TestCredentialStoreCRUD(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	user := testUser(t, store)

	now := time.Now().UTC().Truncate(time.Second)
	cred := &storage.Credential{
		ID:              "cred_crud_001",
		UserID:          user.ID,
		Type:            "passkey",
		CredentialID:    []byte("test-cred-id"),
		PublicKey:       []byte("test-pubkey"),
		AttestationType: "none",
		AAGUID:          []byte("test-aaguid-1234"),
		SignCount:       0,
		DisplayName:     "MacBook Pro",
		CreatedAt:       now,
	}

	// Create
	if err := store.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// Get by ID
	got, err := store.GetCredential(ctx, cred.ID)
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if got.DisplayName != "MacBook Pro" {
		t.Errorf("DisplayName = %q, want %q", got.DisplayName, "MacBook Pro")
	}
	if got.Type != "passkey" {
		t.Errorf("Type = %q, want %q", got.Type, "passkey")
	}
	if string(got.CredentialID) != "test-cred-id" {
		t.Errorf("CredentialID = %q, want %q", string(got.CredentialID), "test-cred-id")
	}

	// Get by credential ID
	got2, err := store.GetCredentialByCredentialID(ctx, []byte("test-cred-id"))
	if err != nil {
		t.Fatalf("GetCredentialByCredentialID: %v", err)
	}
	if got2.ID != cred.ID {
		t.Errorf("ID mismatch: %q != %q", got2.ID, cred.ID)
	}

	// List by user
	creds, err := store.ListCredentialsByUser(ctx, user.ID, "passkey")
	if err != nil {
		t.Fatalf("ListCredentialsByUser: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}

	// List by user (all types)
	allCreds, err := store.ListCredentialsByUser(ctx, user.ID, "")
	if err != nil {
		t.Fatalf("ListCredentialsByUser all: %v", err)
	}
	if len(allCreds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(allCreds))
	}

	// Delete
	if err := store.DeleteCredential(ctx, cred.ID); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	_, err = store.GetCredential(ctx, cred.ID)
	if err != storage.ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}

func TestCredentialSignCountUpdate(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	user := testUser(t, store)

	now := time.Now().UTC().Truncate(time.Second)
	cred := &storage.Credential{
		ID:              "cred_sc_001",
		UserID:          user.ID,
		Type:            "passkey",
		CredentialID:    []byte("sc-test-cred-id"),
		PublicKey:       []byte("sc-test-pubkey"),
		AttestationType: "none",
		AAGUID:          []byte("sc-aaguid-12345"),
		SignCount:       0,
		DisplayName:     "Test Key",
		CreatedAt:       now,
	}

	if err := store.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// Update sign count
	lastUsed := now.Add(1 * time.Hour)
	if err := store.UpdateCredentialSignCount(ctx, cred.ID, 42, lastUsed); err != nil {
		t.Fatalf("UpdateCredentialSignCount: %v", err)
	}

	// Verify
	got, err := store.GetCredential(ctx, cred.ID)
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if got.SignCount != 42 {
		t.Errorf("SignCount = %d, want 42", got.SignCount)
	}
	if got.LastUsedAt == nil {
		t.Fatal("LastUsedAt should not be nil")
	}
	if !got.LastUsedAt.Truncate(time.Second).Equal(lastUsed.Truncate(time.Second)) {
		t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, lastUsed)
	}
}

func TestLastUsedAtTracking(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	user := testUser(t, store)

	now := time.Now().UTC().Truncate(time.Second)
	cred := &storage.Credential{
		ID:              "cred_lu_001",
		UserID:          user.ID,
		Type:            "passkey",
		CredentialID:    []byte("lu-test-cred-id"),
		PublicKey:       []byte("lu-test-pubkey"),
		AttestationType: "none",
		AAGUID:          []byte("lu-aaguid-12345"),
		SignCount:       0,
		DisplayName:     "Last Used Test",
		CreatedAt:       now,
	}

	// Initially, LastUsedAt is nil.
	if err := store.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	got, err := store.GetCredential(ctx, cred.ID)
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if got.LastUsedAt != nil {
		t.Errorf("expected nil LastUsedAt initially, got %v", got.LastUsedAt)
	}

	// Update sign count which also sets last_used_at.
	usedAt := now.Add(30 * time.Minute)
	if err := store.UpdateCredentialSignCount(ctx, cred.ID, 1, usedAt); err != nil {
		t.Fatalf("UpdateCredentialSignCount: %v", err)
	}

	got2, err := store.GetCredential(ctx, cred.ID)
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if got2.LastUsedAt == nil {
		t.Fatal("LastUsedAt should be set after update")
	}
}

func TestBeginRegistration_ReturnsValidOptions(t *testing.T) {
	store := newTestStore(t)
	user := testUser(t, store)

	svc, err := passkey.NewService(testConfig(), store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	creation, sessionData, err := svc.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	// Check that creation options have the correct RP info.
	if creation.Response.RelyingParty.ID != "localhost" {
		t.Errorf("RP ID = %q, want %q", creation.Response.RelyingParty.ID, "localhost")
	}
	if creation.Response.RelyingParty.Name != "Seki Test" {
		t.Errorf("RP Name = %q, want %q", creation.Response.RelyingParty.Name, "Seki Test")
	}

	// Check that challenge is present.
	if len(creation.Response.Challenge) == 0 {
		t.Error("expected non-empty challenge")
	}

	// Check user entity.
	if creation.Response.User.Name != "passkey@example.com" {
		t.Errorf("User Name = %q, want %q", creation.Response.User.Name, "passkey@example.com")
	}

	// Check session data is valid JSON.
	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &sd); err != nil {
		t.Fatalf("session data is not valid JSON: %v", err)
	}
	if sd.Challenge == "" {
		t.Error("expected non-empty challenge in session data")
	}
}

func TestBeginLogin_RequiresCredentials(t *testing.T) {
	store := newTestStore(t)
	user := testUser(t, store)

	svc, err := passkey.NewService(testConfig(), store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Login should fail when user has no credentials.
	_, _, err = svc.BeginLogin(context.Background(), user)
	if err == nil {
		t.Fatal("expected error when user has no credentials")
	}
}

func TestBeginLogin_WithCredentials(t *testing.T) {
	store := newTestStore(t)
	user := testUser(t, store)
	ctx := context.Background()

	// Register a credential for the user.
	now := time.Now().UTC().Truncate(time.Second)
	cred := &storage.Credential{
		ID:              "cred_login_test",
		UserID:          user.ID,
		Type:            "passkey",
		CredentialID:    []byte("login-test-cred-id"),
		PublicKey:       []byte("login-test-pubkey"),
		AttestationType: "none",
		AAGUID:          []byte("login-aaguid-1234"),
		SignCount:       0,
		DisplayName:     "Login Key",
		CreatedAt:       now,
	}
	if err := store.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	svc, err := passkey.NewService(testConfig(), store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	assertion, sessionData, err := svc.BeginLogin(ctx, user)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	if len(assertion.Response.Challenge) == 0 {
		t.Error("expected non-empty challenge")
	}

	// Check allowed credentials list contains our credential.
	if len(assertion.Response.AllowedCredentials) == 0 {
		t.Error("expected non-empty allowed credentials list")
	}

	// Session data should be valid JSON.
	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &sd); err != nil {
		t.Fatalf("session data is not valid JSON: %v", err)
	}
}

func TestBeginDiscoverableLogin(t *testing.T) {
	store := newTestStore(t)

	svc, err := passkey.NewService(testConfig(), store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	assertion, sessionData, err := svc.BeginDiscoverableLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	if len(assertion.Response.Challenge) == 0 {
		t.Error("expected non-empty challenge")
	}

	// Discoverable login should have no allowed credentials.
	if len(assertion.Response.AllowedCredentials) != 0 {
		t.Error("expected empty allowed credentials for discoverable login")
	}

	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionData), &sd); err != nil {
		t.Fatalf("session data is not valid JSON: %v", err)
	}
}

func TestCredentialStorageRoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	user := testUser(t, store)

	now := time.Now().UTC().Truncate(time.Second)
	lastUsed := now.Add(-10 * time.Minute)
	cred := &storage.Credential{
		ID:              "cred_rt_001",
		UserID:          user.ID,
		Type:            "passkey",
		CredentialID:    []byte{0x01, 0x02, 0x03, 0xff},
		PublicKey:       []byte{0xaa, 0xbb, 0xcc},
		AttestationType: "packed",
		AAGUID:          []byte{0x10, 0x20, 0x30, 0x40},
		SignCount:       7,
		DisplayName:     "My YubiKey",
		LastUsedAt:      &lastUsed,
		CreatedAt:       now,
	}

	if err := store.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	got, err := store.GetCredential(ctx, cred.ID)
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}

	// Verify all fields round-trip correctly.
	if got.UserID != cred.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, cred.UserID)
	}
	if got.Type != "passkey" {
		t.Errorf("Type = %q, want %q", got.Type, "passkey")
	}
	if string(got.CredentialID) != string(cred.CredentialID) {
		t.Errorf("CredentialID mismatch")
	}
	if string(got.PublicKey) != string(cred.PublicKey) {
		t.Errorf("PublicKey mismatch")
	}
	if got.AttestationType != "packed" {
		t.Errorf("AttestationType = %q, want %q", got.AttestationType, "packed")
	}
	if string(got.AAGUID) != string(cred.AAGUID) {
		t.Errorf("AAGUID mismatch")
	}
	if got.SignCount != 7 {
		t.Errorf("SignCount = %d, want 7", got.SignCount)
	}
	if got.DisplayName != "My YubiKey" {
		t.Errorf("DisplayName = %q, want %q", got.DisplayName, "My YubiKey")
	}
	if got.LastUsedAt == nil {
		t.Fatal("LastUsedAt should not be nil")
	}
	if !got.LastUsedAt.Truncate(time.Second).Equal(lastUsed.Truncate(time.Second)) {
		t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, lastUsed)
	}
}
