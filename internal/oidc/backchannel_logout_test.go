package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/session"
	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

func TestBackChannelLogout_PostToClientURI(t *testing.T) {
	store, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ctx := context.Background()
	now := time.Now().UTC()

	// Create a test user.
	err = store.CreateUser(ctx, &storage.User{
		ID:          "bcl-user-1",
		Email:       "bcl@example.com",
		DisplayName: "BCL User",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Track logout token deliveries.
	var mu sync.Mutex
	var receivedTokens []string

	bclServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		logoutToken := r.PostFormValue("logout_token")
		mu.Lock()
		receivedTokens = append(receivedTokens, logoutToken)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(bclServer.Close)

	// Create a client with backchannel_logout_uri.
	err = store.CreateClient(ctx, &storage.Client{
		ID:                          "bcl-client",
		Name:                        "BCL Client",
		SecretHash:                  "",
		RedirectURIs:                []string{"https://app.example.com/callback"},
		GrantTypes:                  []string{"authorization_code"},
		Scopes:                      []string{"openid"},
		BackChannelLogoutURI:        bclServer.URL,
		BackChannelLogoutSessionReq: true,
		CreatedAt:                   now,
		UpdatedAt:                   now,
	})
	if err != nil {
		t.Fatalf("create bcl client: %v", err)
	}

	signer := newTestSigner(t)
	sessMgr := session.NewManager(store, session.Config{})
	provider := oidc.NewProvider("https://auth.example.com", signer, store,
		oidc.WithSessionManager(sessMgr))

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	// Create a session for the user.
	sess, err := sessMgr.Create(ctx, "bcl-user-1", "", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Perform logout.
	form := url.Values{"redirect_uri": {""}}
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "seki_session", Value: sess.ID})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}

	// Wait a bit for async goroutine to complete.
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(receivedTokens) == 0 {
		t.Fatal("expected at least one logout token to be delivered")
	}
}

func TestBackChannelLogout_TokenHasCorrectClaims(t *testing.T) {
	store, err := storage.New(storage.TestDatabaseConfig())
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ctx := context.Background()
	now := time.Now().UTC()

	err = store.CreateUser(ctx, &storage.User{
		ID:          "bcl-user-2",
		Email:       "bcl2@example.com",
		DisplayName: "BCL User 2",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	var mu sync.Mutex
	var receivedTokens []string

	bclServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		logoutToken := r.PostFormValue("logout_token")
		mu.Lock()
		receivedTokens = append(receivedTokens, logoutToken)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(bclServer.Close)

	err = store.CreateClient(ctx, &storage.Client{
		ID:                          "bcl-client-2",
		Name:                        "BCL Client 2",
		RedirectURIs:                []string{"https://app.example.com/callback"},
		GrantTypes:                  []string{"authorization_code"},
		Scopes:                      []string{"openid"},
		BackChannelLogoutURI:        bclServer.URL,
		BackChannelLogoutSessionReq: true,
		CreatedAt:                   now,
		UpdatedAt:                   now,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	signer := newTestSigner(t)
	sessMgr := session.NewManager(store, session.Config{})
	provider := oidc.NewProvider("https://auth.example.com", signer, store,
		oidc.WithSessionManager(sessMgr))

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	sess, err := sessMgr.Create(ctx, "bcl-user-2", "", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	form := url.Values{"redirect_uri": {""}}
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "seki_session", Value: sess.ID})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(receivedTokens) == 0 {
		t.Fatal("expected logout token")
	}

	// Verify the logout token claims.
	claims, err := signer.Verify(receivedTokens[0])
	if err != nil {
		t.Fatalf("verify logout token: %v", err)
	}

	if claims["iss"] != "https://auth.example.com" {
		t.Errorf("iss = %v, want https://auth.example.com", claims["iss"])
	}
	if claims["sub"] != "bcl-user-2" {
		t.Errorf("sub = %v, want bcl-user-2", claims["sub"])
	}
	if claims["aud"] != "bcl-client-2" {
		t.Errorf("aud = %v, want bcl-client-2", claims["aud"])
	}
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Error("missing jti claim")
	}

	// Check events claim.
	events, ok := claims["events"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid events claim")
	}
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Error("missing backchannel-logout event in events claim")
	}

	// Check sid claim is present (since backchannel_logout_session_required is true).
	if claims["sid"] == nil || claims["sid"] == "" {
		t.Error("missing sid claim in logout token")
	}
}

func TestIDToken_ContainsSIDClaim(t *testing.T) {
	h := newTokenHarness(t)

	verifier := "sid-test-verifier"
	challenge := computeS256Challenge(verifier)

	h.createAuthCode(t, "sid-code", "test-client", "user-1",
		"https://app.example.com/callback", challenge, "sid-nonce",
		[]string{"openid", "profile"}, time.Now().Add(10*time.Minute))

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"sid-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)
	idTokenStr, ok := body["id_token"].(string)
	if !ok || idTokenStr == "" {
		t.Fatal("missing id_token")
	}

	idClaims, err := h.signer.Verify(idTokenStr)
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}

	if idClaims["sid"] == nil || idClaims["sid"] == "" {
		t.Error("missing sid claim in id_token")
	}
}

// Suppress unused import warnings.
var (
	_ = json.Marshal
	_ crypto.Signer
)
