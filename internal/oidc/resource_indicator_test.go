package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/session"
	"github.com/entoten/seki/internal/storage"
	"github.com/golang-jwt/jwt/v5"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

type resourceHarness struct {
	store    storage.Storage
	provider *oidc.Provider
	mux      *http.ServeMux
	signer   crypto.Signer
	cookie   *http.Cookie
}

func newResourceHarness(t *testing.T) *resourceHarness {
	t.Helper()

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
		ID:          "user-1",
		Email:       "test@example.com",
		DisplayName: "Test User",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	hasher := crypto.NewBcryptHasher(4)
	secretHash, err := hasher.Hash("test-secret")
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}

	err = store.CreateClient(ctx, &storage.Client{
		ID:           "resource-client",
		Name:         "Resource Test Client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code", "client_credentials", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email"},
		PKCERequired: false,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	signer := newTestSigner(t)
	sessMgr := session.NewManager(store, session.Config{
		CookieName:      "sid",
		AbsoluteTimeout: time.Hour,
		CookieSecure:    false,
	})

	sess, err := sessMgr.Create(ctx, "user-1", "", "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	provider := oidc.NewProvider("https://auth.example.com", signer, store,
		oidc.WithSessionManager(sessMgr))

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &resourceHarness{
		store:    store,
		provider: provider,
		mux:      mux,
		signer:   signer,
		cookie:   &http.Cookie{Name: "sid", Value: sess.ID},
	}
}

func TestResource_ClientCredentialsWithResource(t *testing.T) {
	h := newResourceHarness(t)

	params := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid"},
		"resource":   {"https://api.example.com"},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("resource-client", "test-secret")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var tokenResp map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&tokenResp)

	accessToken := tokenResp["access_token"].(string)

	// Parse the access token to check the aud claim.
	claims, err := h.signer.Verify(accessToken)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}

	aud, _ := claims["aud"].(string)
	if aud != "https://api.example.com" {
		t.Errorf("aud = %q, want https://api.example.com", aud)
	}
	clientIDClaim, _ := claims["client_id"].(string)
	if clientIDClaim != "resource-client" {
		t.Errorf("client_id = %q, want resource-client", clientIDClaim)
	}
}

func TestResource_ClientCredentialsWithoutResource(t *testing.T) {
	h := newResourceHarness(t)

	params := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid"},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("resource-client", "test-secret")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var tokenResp map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&tokenResp)

	accessToken := tokenResp["access_token"].(string)

	claims, err := h.signer.Verify(accessToken)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}

	// Without resource, aud should be client_id.
	aud, _ := claims["aud"].(string)
	if aud != "resource-client" {
		t.Errorf("aud = %q, want resource-client (backward compat)", aud)
	}
}

func TestResource_AuthCodeFlowPreservesResource(t *testing.T) {
	h := newResourceHarness(t)

	// Step 1: Authorize with resource parameter.
	authParams := url.Values{
		"client_id":     {"resource-client"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"test-state"},
		"resource":      {"https://api.example.com/v1"},
	}

	authReq := httptest.NewRequest(http.MethodGet, "/authorize?"+authParams.Encode(), nil)
	authReq.AddCookie(h.cookie)
	authRec := httptest.NewRecorder()
	h.mux.ServeHTTP(authRec, authReq)

	authResp := authRec.Result()
	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", authResp.StatusCode)
	}

	loc, _ := authResp.Location()
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code in redirect")
	}

	// Verify resource is stored in auth code.
	ac, err := h.store.GetAuthCode(context.Background(), code)
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if ac.Resource != "https://api.example.com/v1" {
		t.Errorf("auth code resource = %q, want https://api.example.com/v1", ac.Resource)
	}

	// Step 2: Exchange code for tokens.
	tokenParams := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://app.example.com/callback"},
	}

	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenParams.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth("resource-client", "test-secret")
	tokenRec := httptest.NewRecorder()
	h.mux.ServeHTTP(tokenRec, tokenReq)

	tokenResp := tokenRec.Result()
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", tokenResp.StatusCode)
	}

	var tokenBody map[string]interface{}
	_ = json.NewDecoder(tokenResp.Body).Decode(&tokenBody)

	accessToken := tokenBody["access_token"].(string)

	// Verify aud is the resource.
	claims, err := h.signer.Verify(accessToken)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}

	aud, _ := claims["aud"].(string)
	if aud != "https://api.example.com/v1" {
		t.Errorf("aud = %q, want https://api.example.com/v1", aud)
	}
}

func TestResource_AuthCodeFlowWithoutResource(t *testing.T) {
	h := newResourceHarness(t)

	// Step 1: Authorize WITHOUT resource parameter.
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h256 := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h256[:])

	authParams := url.Values{
		"client_id":             {"resource-client"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"test-state"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	authReq := httptest.NewRequest(http.MethodGet, "/authorize?"+authParams.Encode(), nil)
	authReq.AddCookie(h.cookie)
	authRec := httptest.NewRecorder()
	h.mux.ServeHTTP(authRec, authReq)

	authResp := authRec.Result()
	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", authResp.StatusCode)
	}

	loc, _ := authResp.Location()
	code := loc.Query().Get("code")

	// Step 2: Exchange code for tokens.
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/callback"},
		"code_verifier": {codeVerifier},
	}

	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenParams.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth("resource-client", "test-secret")
	tokenRec := httptest.NewRecorder()
	h.mux.ServeHTTP(tokenRec, tokenReq)

	tokenResp := tokenRec.Result()
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", tokenResp.StatusCode)
	}

	var tokenBody map[string]interface{}
	_ = json.NewDecoder(tokenResp.Body).Decode(&tokenBody)

	accessToken := tokenBody["access_token"].(string)

	// Verify aud is client_id (backward compat).
	claims, err := h.signer.Verify(accessToken)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}

	aud, _ := claims["aud"].(string)
	if aud != "resource-client" {
		t.Errorf("aud = %q, want resource-client (backward compat)", aud)
	}
}

// Suppress unused import warnings.
var _ jwt.MapClaims
