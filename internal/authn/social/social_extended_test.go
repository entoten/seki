package social

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/storage"
	"github.com/Monet/seki/internal/storage/sqlite"
)

func newTestStoreAndService(t *testing.T) (*Service, storage.Storage) {
	t.Helper()
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
		"github": {ClientID: "ghid", ClientSecret: "ghsecret"},
	}
	svc := NewService(cfg, store)
	return svc, store
}

func TestFindOrCreateUser_Creates(t *testing.T) {
	svc, store := newTestStoreAndService(t)
	ctx := context.Background()

	su := &SocialUser{
		Provider:   "google",
		ProviderID: "goog-123",
		Email:      "newuser@example.com",
		Name:       "New User",
	}

	user, isNew, err := svc.FindOrCreateUser(ctx, su)
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}
	if !isNew {
		t.Error("expected isNew=true for new user")
	}
	if user.Email != "newuser@example.com" {
		t.Errorf("email = %q, want newuser@example.com", user.Email)
	}

	// Verify in store.
	got, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.DisplayName != "New User" {
		t.Errorf("display_name = %q, want New User", got.DisplayName)
	}
}

func TestFindOrCreateUser_FindsExisting(t *testing.T) {
	svc, store := newTestStoreAndService(t)
	ctx := context.Background()

	// Pre-create user.
	err := store.CreateUser(ctx, &storage.User{
		ID:        "existing-user",
		Email:     "existing@example.com",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	su := &SocialUser{
		Provider:   "google",
		ProviderID: "goog-456",
		Email:      "existing@example.com",
		Name:       "Existing User",
	}

	user, isNew, err := svc.FindOrCreateUser(ctx, su)
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}
	if isNew {
		t.Error("expected isNew=false for existing user")
	}
	if user.ID != "existing-user" {
		t.Errorf("ID = %q, want existing-user", user.ID)
	}
}

func TestLinkAccount(t *testing.T) {
	svc, store := newTestStoreAndService(t)
	ctx := context.Background()

	err := store.CreateUser(ctx, &storage.User{
		ID:        "link-user",
		Email:     "link@example.com",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	su := &SocialUser{
		Provider:   "google",
		ProviderID: "goog-789",
		Email:      "link@example.com",
		Name:       "Link User",
	}

	err = svc.LinkAccount(ctx, su, "link-user")
	if err != nil {
		t.Fatalf("LinkAccount: %v", err)
	}

	// Verify credential was stored.
	creds, err := store.GetCredentialsByUserAndType(ctx, "link-user", "social:google")
	if err != nil {
		t.Fatalf("GetCredentialsByUserAndType: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if string(creds[0].Secret) != "goog-789" {
		t.Errorf("secret = %q, want goog-789", string(creds[0].Secret))
	}
}

func TestExchange_WithMockServer(t *testing.T) {
	// Create mock token endpoint.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
		})
	}))
	defer tokenServer.Close()

	// Create mock userinfo endpoint.
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mock-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":     "goog-user-123",
			"email":   "social@example.com",
			"name":    "Social User",
			"picture": "https://example.com/avatar.jpg",
		})
	}))
	defer userInfoServer.Close()

	// Replace the known providers with our mock URLs.
	svc := &Service{
		providers: map[string]*Provider{
			"google": {
				Name:         "google",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL:     tokenServer.URL,
				UserInfoURL:  userInfoServer.URL,
				Scopes:       []string{"openid", "email", "profile"},
			},
		},
		client: &http.Client{},
	}

	su, err := svc.Exchange(context.Background(), "google", "test-code", "https://example.com/callback")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if su.Provider != "google" {
		t.Errorf("provider = %q, want google", su.Provider)
	}
	if su.ProviderID != "goog-user-123" {
		t.Errorf("provider_id = %q, want goog-user-123", su.ProviderID)
	}
	if su.Email != "social@example.com" {
		t.Errorf("email = %q, want social@example.com", su.Email)
	}
	if su.Name != "Social User" {
		t.Errorf("name = %q, want Social User", su.Name)
	}
}

func TestExchange_GitHub(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "gh-token",
		})
	}))
	defer tokenServer.Close()

	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         float64(12345),
			"email":      "ghuser@example.com",
			"name":       "",
			"login":      "ghuser",
			"avatar_url": "https://github.com/avatar.jpg",
		})
	}))
	defer userInfoServer.Close()

	svc := &Service{
		providers: map[string]*Provider{
			"github": {
				Name:         "github",
				ClientID:     "gh-client",
				ClientSecret: "gh-secret",
				TokenURL:     tokenServer.URL,
				UserInfoURL:  userInfoServer.URL,
			},
		},
		client: &http.Client{},
	}

	su, err := svc.Exchange(context.Background(), "github", "code", "https://example.com/cb")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if su.ProviderID != "12345" {
		t.Errorf("provider_id = %q, want 12345", su.ProviderID)
	}
	if su.Name != "ghuser" {
		t.Errorf("name = %q, want ghuser (login fallback)", su.Name)
	}
}

func TestExchange_UnknownProvider(t *testing.T) {
	svc := &Service{providers: map[string]*Provider{}, client: &http.Client{}}

	_, err := svc.Exchange(context.Background(), "unknown", "code", "url")
	if err != ErrUnknownProvider {
		t.Fatalf("expected ErrUnknownProvider, got %v", err)
	}
}

func TestNewService_IgnoresUnknownProvider(t *testing.T) {
	cfg := map[string]config.SocialProvider{
		"twitter": {ClientID: "tid", ClientSecret: "tsecret"},
	}
	svc := NewService(cfg, nil)
	_, err := svc.GetProvider("twitter")
	if err != ErrUnknownProvider {
		t.Fatalf("expected ErrUnknownProvider for unsupported provider, got %v", err)
	}
}

func TestStringFromMap(t *testing.T) {
	m := map[string]interface{}{
		"str":  "hello",
		"num":  42,
		"nil":  nil,
	}
	if got := stringFromMap(m, "str"); got != "hello" {
		t.Errorf("str = %q, want hello", got)
	}
	if got := stringFromMap(m, "num"); got != "" {
		t.Errorf("num = %q, want empty (not a string)", got)
	}
	if got := stringFromMap(m, "missing"); got != "" {
		t.Errorf("missing = %q, want empty", got)
	}
}
