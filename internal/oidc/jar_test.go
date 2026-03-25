package oidc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/session"
	"github.com/entoten/seki/internal/storage"
	"github.com/golang-jwt/jwt/v5"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

type jarHarness struct {
	store      storage.Storage
	provider   *oidc.Provider
	mux        *http.ServeMux
	cookie     *http.Cookie
	clientPriv ed25519.PrivateKey
	clientPub  ed25519.PublicKey
}

func newJARHarness(t *testing.T) *jarHarness {
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
		ID:        "user-1",
		Email:     "test@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Generate client key pair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Serve JWKS.
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		},
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jwksServer.Close)

	err = store.CreateClient(ctx, &storage.Client{
		ID:                      "jar-client",
		Name:                    "JAR Test Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid", "profile", "email"},
		PKCERequired:            false,
		JWKsURI:                 jwksServer.URL,
		TokenEndpointAuthMethod: "private_key_jwt",
		CreatedAt:               now,
		UpdatedAt:               now,
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

	return &jarHarness{
		store:      store,
		provider:   provider,
		mux:        mux,
		cookie:     &http.Cookie{Name: "sid", Value: sess.ID},
		clientPriv: priv,
		clientPub:  pub,
	}
}

func (h *jarHarness) signJAR(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(h.clientPriv)
	if err != nil {
		t.Fatalf("sign JAR: %v", err)
	}
	return signed
}

func TestJAR_ValidRequest(t *testing.T) {
	h := newJARHarness(t)

	jarClaims := jwt.MapClaims{
		"iss":           "jar-client",
		"aud":           "https://auth.example.com",
		"client_id":     "jar-client",
		"redirect_uri":  "https://app.example.com/callback",
		"response_type": "code",
		"scope":         "openid profile",
		"state":         "jar-state",
		"nonce":         "jar-nonce",
	}
	requestJWT := h.signJAR(t, jarClaims)

	params := url.Values{
		"client_id": {"jar-client"},
		"request":   {requestJWT},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("no Location header: %v", err)
	}

	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("expected code in redirect, got none")
	}
	if loc.Query().Get("state") != "jar-state" {
		t.Errorf("state = %q, want jar-state", loc.Query().Get("state"))
	}
}

func TestJAR_InvalidSignature(t *testing.T) {
	h := newJARHarness(t)

	// Sign with a different key.
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss":           "jar-client",
		"aud":           "https://auth.example.com",
		"client_id":     "jar-client",
		"redirect_uri":  "https://app.example.com/callback",
		"response_type": "code",
		"scope":         "openid profile",
		"state":         "jar-state",
	})
	badJWT, _ := token.SignedString(wrongPriv)

	params := url.Values{
		"client_id": {"jar-client"},
		"request":   {badJWT},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid signature, got %d", resp.StatusCode)
	}
}

func TestJAR_ClientIDMismatch(t *testing.T) {
	h := newJARHarness(t)

	jarClaims := jwt.MapClaims{
		"iss":           "jar-client",
		"aud":           "https://auth.example.com",
		"client_id":     "wrong-client",
		"redirect_uri":  "https://app.example.com/callback",
		"response_type": "code",
		"scope":         "openid profile",
		"state":         "jar-state",
	}
	requestJWT := h.signJAR(t, jarClaims)

	params := url.Values{
		"client_id": {"jar-client"},
		"request":   {requestJWT},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for client_id mismatch, got %d", resp.StatusCode)
	}
}

func TestJAR_JWTClaimsOverrideQueryParams(t *testing.T) {
	h := newJARHarness(t)

	// Query params have one state, JWT has another. JWT should win.
	jarClaims := jwt.MapClaims{
		"iss":           "jar-client",
		"aud":           "https://auth.example.com",
		"redirect_uri":  "https://app.example.com/callback",
		"response_type": "code",
		"scope":         "openid profile",
		"state":         "jwt-state",
		"nonce":         "jwt-nonce",
	}
	requestJWT := h.signJAR(t, jarClaims)

	params := url.Values{
		"client_id":     {"jar-client"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"query-state"},
		"request":       {requestJWT},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	req.AddCookie(h.cookie)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	loc, _ := resp.Location()
	if loc.Query().Get("state") != "jwt-state" {
		t.Errorf("state = %q, want jwt-state (JWT should override query)", loc.Query().Get("state"))
	}
}

// Ensure the test uses the crypto signer (avoid unused import).
var _ crypto.Signer = (*crypto.Ed25519Signer)(nil)
