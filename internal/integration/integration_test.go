package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/internal/crypto"
	"github.com/Monet/seki/internal/oidc"
	"github.com/Monet/seki/internal/session"
	"github.com/Monet/seki/internal/storage"
	_ "github.com/Monet/seki/internal/storage/sqlite"
	"golang.org/x/crypto/bcrypt"
)

// TestFullOIDCAuthorizationCodeFlow exercises the entire critical OIDC path
// end-to-end using an in-memory SQLite store:
//
//  1. GET /authorize without session -> redirect to /login
//  2. POST /login with valid credentials -> redirect to /authorize
//  3. GET /authorize with session -> redirect with code
//  4. POST /token with code -> get tokens
//  5. GET /userinfo with access_token -> get claims
//  6. POST /token with refresh_token -> get new tokens
//  7. POST /logout -> session destroyed
func TestFullOIDCAuthorizationCodeFlow(t *testing.T) {
	// --- Setup ---
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

	// Create test user.
	err = store.CreateUser(ctx, &storage.User{
		ID:          "user-e2e",
		Email:       "e2e@example.com",
		DisplayName: "E2E User",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create password credential.
	pwHash, _ := bcrypt.GenerateFromPassword([]byte("e2epassword"), bcrypt.MinCost)
	err = store.CreateCredential(ctx, &storage.Credential{
		ID:        "cred-e2e-pw",
		UserID:    "user-e2e",
		Type:      "password",
		Secret:    pwHash,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}

	// Create test client.
	hasher := crypto.NewBcryptHasher(4)
	secretHash, _ := hasher.Hash("client-secret-e2e")
	err = store.CreateClient(ctx, &storage.Client{
		ID:           "e2e-client",
		Name:         "E2E Client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email"},
		PKCERequired: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Create signer.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := crypto.NewEd25519SignerFromKey(priv, "e2e-key", "https://auth.example.com", time.Hour)

	// Create session manager.
	sessCfg := session.Config{CookieName: "seki_session"}
	sessMgr := session.NewManager(store, sessCfg)

	// Create provider.
	provider := oidc.NewProvider("https://auth.example.com", signer, store,
		oidc.WithSessionManager(sessMgr),
		oidc.WithAuthenticationConfig(config.AuthenticationConfig{
			Password: config.PasswordConfig{Enabled: true},
		}),
	)
	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	// PKCE verifier/challenge.
	verifier := "e2e-pkce-verifier-for-testing-twelve"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	authParams := url.Values{
		"client_id":             {"e2e-client"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"e2e-state"},
		"nonce":                 {"e2e-nonce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	// --- Step 1: GET /authorize without session -> redirect to /login ---
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+authParams.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("step1: expected 302, got %d", rec.Code)
	}
	loginLoc, _ := rec.Result().Location()
	if loginLoc.Path != "/login" {
		t.Fatalf("step1: expected /login, got %q", loginLoc.Path)
	}
	if loginLoc.Query().Get("client_id") != "e2e-client" {
		t.Fatal("step1: OIDC params not preserved in login redirect")
	}

	// --- Step 2: POST /login with valid credentials ---
	loginForm := url.Values{
		"email":    {"e2e@example.com"},
		"password": {"e2epassword"},
	}
	// Copy OIDC params from login redirect.
	for _, k := range []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"} {
		if v := loginLoc.Query().Get(k); v != "" {
			loginForm.Set(k, v)
		}
	}

	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(loginForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("step2: expected 302, got %d", rec.Code)
	}
	authLoc, _ := rec.Result().Location()
	if authLoc.Path != "/authorize" {
		t.Fatalf("step2: expected /authorize, got %q", authLoc.Path)
	}

	// Extract session cookie.
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "seki_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("step2: no session cookie set")
	}

	// --- Step 3: GET /authorize with session -> redirect with code ---
	req = httptest.NewRequest(http.MethodGet, authLoc.RequestURI(), nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("step3: expected 302, got %d", rec.Code)
	}
	callbackLoc, _ := rec.Result().Location()
	code := callbackLoc.Query().Get("code")
	if code == "" {
		t.Fatal("step3: no authorization code in redirect")
	}
	if callbackLoc.Query().Get("state") != "e2e-state" {
		t.Fatal("step3: state not preserved")
	}

	// --- Step 4: POST /token with code -> get tokens ---
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"e2e-client"},
		"client_secret": {"client-secret-e2e"},
		"code_verifier": {verifier},
	}

	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenParams.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("step4: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var tokenResp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&tokenResp)

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("step4: missing access_token")
	}
	idToken, ok := tokenResp["id_token"].(string)
	if !ok || idToken == "" {
		t.Fatal("step4: missing id_token")
	}
	refreshToken, ok := tokenResp["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatal("step4: missing refresh_token")
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Fatalf("step4: token_type = %v, want Bearer", tokenResp["token_type"])
	}

	// Verify ID token claims.
	idClaims, err := signer.Verify(idToken)
	if err != nil {
		t.Fatalf("step4: verify id_token: %v", err)
	}
	if idClaims["sub"] != "user-e2e" {
		t.Errorf("step4: id_token sub = %v, want user-e2e", idClaims["sub"])
	}
	if idClaims["nonce"] != "e2e-nonce" {
		t.Errorf("step4: id_token nonce = %v, want e2e-nonce", idClaims["nonce"])
	}
	if idClaims["email"] != "e2e@example.com" {
		t.Errorf("step4: id_token email = %v", idClaims["email"])
	}

	// --- Step 5: GET /userinfo with access_token -> get claims ---
	req = httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("step5: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var userInfo map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&userInfo)
	if userInfo["sub"] != "user-e2e" {
		t.Errorf("step5: sub = %v, want user-e2e", userInfo["sub"])
	}
	if userInfo["email"] != "e2e@example.com" {
		t.Errorf("step5: email = %v", userInfo["email"])
	}
	if userInfo["name"] != "E2E User" {
		t.Errorf("step5: name = %v", userInfo["name"])
	}

	// --- Step 6: POST /token with refresh_token -> get new tokens ---
	refreshParams := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"e2e-client"},
		"client_secret": {"client-secret-e2e"},
	}

	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshParams.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("step6: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var refreshResp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&refreshResp)
	if refreshResp["access_token"] == nil || refreshResp["access_token"] == "" {
		t.Fatal("step6: missing access_token in refresh response")
	}
	if refreshResp["refresh_token"] == nil || refreshResp["refresh_token"] == "" {
		t.Fatal("step6: missing new refresh_token")
	}
	if refreshResp["refresh_token"] == refreshToken {
		t.Fatal("step6: new refresh_token should differ from old one")
	}

	// --- Step 7: POST /logout -> session destroyed ---
	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("step7: expected 302, got %d", rec.Code)
	}

	// Session cookie should be cleared.
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "seki_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("step7: session cookie not cleared")
	}

	// Verify session is gone: /authorize should redirect to /login again.
	req = httptest.NewRequest(http.MethodGet, "/authorize?"+authParams.Encode(), nil)
	req.AddCookie(sessionCookie) // old cookie
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("step7 verify: expected 302, got %d", rec.Code)
	}
	postLogoutLoc, _ := rec.Result().Location()
	if postLogoutLoc.Path != "/login" {
		t.Fatalf("step7 verify: expected /login after logout, got %q", postLogoutLoc.Path)
	}
}
