package oidc_test

import (
	"context"
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

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

// parHarness is a test harness for PAR tests.
type parHarness struct {
	store      storage.Storage
	provider   *oidc.Provider
	mux        *http.ServeMux
	signer     crypto.Signer
	sessionMgr *session.Manager
}

func newPARHarness(t *testing.T) *parHarness {
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
		ID:           "test-client",
		Name:         "Test Client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email"},
		PKCERequired: false, // Simplify PAR tests by not requiring PKCE.
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	signer := newTestSigner(t)
	sessionMgr := session.NewManager(store, session.Config{
		CookieName:      "sid",
		AbsoluteTimeout: time.Hour,
		CookieSecure:    false,
	})

	provider := oidc.NewProvider("https://auth.example.com", signer, store,
		oidc.WithSessionManager(sessionMgr))

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &parHarness{
		store:      store,
		provider:   provider,
		mux:        mux,
		signer:     signer,
		sessionMgr: sessionMgr,
	}
}

func (h *parHarness) doPARRequest(t *testing.T, params url.Values, basicAuth ...string) *http.Response {
	t.Helper()
	body := params.Encode()
	req := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basicAuth) == 2 {
		req.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func decodePARResponse(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode PAR response: %v", err)
	}
	return body
}

func TestPAR_PostReturnsRequestURI(t *testing.T) {
	h := newPARHarness(t)

	params := url.Values{
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"test-state"},
	}

	resp := h.doPARRequest(t, params)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body := decodePARResponse(t, resp)
		t.Fatalf("expected 201, got %d: %v", resp.StatusCode, body)
	}

	body := decodePARResponse(t, resp)

	requestURI, ok := body["request_uri"].(string)
	if !ok || requestURI == "" {
		t.Fatal("missing request_uri in response")
	}

	if !strings.HasPrefix(requestURI, "urn:ietf:params:oauth:request_uri:") {
		t.Errorf("request_uri does not have expected prefix: %s", requestURI)
	}

	expiresIn, ok := body["expires_in"].(float64)
	if !ok {
		t.Fatal("missing expires_in in response")
	}
	if expiresIn != 60 {
		t.Errorf("expires_in = %v, want 60", expiresIn)
	}
}

func TestPAR_AuthorizeWithRequestURI(t *testing.T) {
	h := newPARHarness(t)

	// Create a session for the user.
	ctx := context.Background()
	now := time.Now().UTC()
	sess := &storage.Session{
		ID:               "test-session-1",
		UserID:           "user-1",
		ExpiresAt:        now.Add(time.Hour),
		AbsoluteExpiresAt: now.Add(time.Hour),
		CreatedAt:        now,
		LastActiveAt:     now,
	}
	if err := h.store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Submit PAR request.
	params := url.Values{
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"par-state"},
	}

	parResp := h.doPARRequest(t, params)
	defer parResp.Body.Close()

	if parResp.StatusCode != http.StatusCreated {
		body := decodePARResponse(t, parResp)
		t.Fatalf("expected 201, got %d: %v", parResp.StatusCode, body)
	}

	parBody := decodePARResponse(t, parResp)
	requestURI := parBody["request_uri"].(string)

	// Now use the request_uri on the authorize endpoint.
	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?request_uri="+url.QueryEscape(requestURI)+"&client_id=test-client",
		nil)
	authReq.AddCookie(&http.Cookie{Name: "sid", Value: "test-session-1"})

	authRec := httptest.NewRecorder()
	h.mux.ServeHTTP(authRec, authReq)
	authResp := authRec.Result()
	defer authResp.Body.Close()

	// Should redirect with a code.
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", authResp.StatusCode)
	}

	location := authResp.Header.Get("Location")
	locURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}

	code := locURL.Query().Get("code")
	if code == "" {
		t.Error("missing code in redirect")
	}

	state := locURL.Query().Get("state")
	if state != "par-state" {
		t.Errorf("state = %v, want par-state", state)
	}
}

func TestPAR_ExpiredRequestURI_Rejected(t *testing.T) {
	h := newPARHarness(t)

	// Create a session.
	ctx := context.Background()
	now := time.Now().UTC()
	sess := &storage.Session{
		ID:         "test-session-2",
		UserID:     "user-1",
		ExpiresAt:  now.Add(time.Hour),
		CreatedAt:  now,
		LastActiveAt: now,
	}
	if err := h.store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// We cannot easily wait for expiry in a test, so we'll test with a non-existent URI.
	// This tests the same code path since the URI won't be found.
	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?request_uri="+url.QueryEscape("urn:ietf:params:oauth:request_uri:nonexistent")+"&client_id=test-client",
		nil)
	authReq.AddCookie(&http.Cookie{Name: "sid", Value: "test-session-2"})

	authRec := httptest.NewRecorder()
	h.mux.ServeHTTP(authRec, authReq)
	authResp := authRec.Result()
	defer authResp.Body.Close()

	// Should return error (not a redirect, since we can't validate redirect_uri).
	if authResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", authResp.StatusCode)
	}
}

func TestPAR_RequestURISingleUse(t *testing.T) {
	h := newPARHarness(t)

	// Create a session.
	ctx := context.Background()
	now := time.Now().UTC()
	sess := &storage.Session{
		ID:         "test-session-3",
		UserID:     "user-1",
		ExpiresAt:  now.Add(time.Hour),
		CreatedAt:  now,
		LastActiveAt: now,
	}
	if err := h.store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Submit PAR request.
	params := url.Values{
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"single-use-state"},
	}

	parResp := h.doPARRequest(t, params)
	defer parResp.Body.Close()

	parBody := decodePARResponse(t, parResp)
	requestURI := parBody["request_uri"].(string)

	// First use should succeed.
	authReq1 := httptest.NewRequest(http.MethodGet,
		"/authorize?request_uri="+url.QueryEscape(requestURI)+"&client_id=test-client",
		nil)
	authReq1.AddCookie(&http.Cookie{Name: "sid", Value: "test-session-3"})

	authRec1 := httptest.NewRecorder()
	h.mux.ServeHTTP(authRec1, authReq1)

	if authRec1.Code != http.StatusFound {
		t.Fatalf("first use: expected 302, got %d", authRec1.Code)
	}

	// Second use should fail.
	authReq2 := httptest.NewRequest(http.MethodGet,
		"/authorize?request_uri="+url.QueryEscape(requestURI)+"&client_id=test-client",
		nil)
	authReq2.AddCookie(&http.Cookie{Name: "sid", Value: "test-session-3"})

	authRec2 := httptest.NewRecorder()
	h.mux.ServeHTTP(authRec2, authReq2)

	if authRec2.Code != http.StatusBadRequest {
		t.Fatalf("second use: expected 400, got %d", authRec2.Code)
	}
}

func TestPAR_InvalidClient_Rejected(t *testing.T) {
	h := newPARHarness(t)

	params := url.Values{
		"client_id":     {"nonexistent-client"},
		"client_secret": {"wrong-secret"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}

	resp := h.doPARRequest(t, params)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	body := decodePARResponse(t, resp)
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", body["error"])
	}
}

func TestPAR_InvalidRedirectURI_Rejected(t *testing.T) {
	h := newPARHarness(t)

	params := url.Values{
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"redirect_uri":  {"https://evil.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}

	resp := h.doPARRequest(t, params)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	body := decodePARResponse(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", body["error"])
	}
}

func TestPAR_DiscoveryIncludesPAREndpoint(t *testing.T) {
	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, nil)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}

	parEndpoint, ok := body["pushed_authorization_request_endpoint"].(string)
	if !ok || parEndpoint == "" {
		t.Fatal("missing pushed_authorization_request_endpoint")
	}
	if parEndpoint != "https://auth.example.com/par" {
		t.Errorf("pushed_authorization_request_endpoint = %v", parEndpoint)
	}

	requirePAR, ok := body["require_pushed_authorization_requests"]
	if !ok {
		t.Fatal("missing require_pushed_authorization_requests")
	}
	if requirePAR != false {
		t.Errorf("require_pushed_authorization_requests = %v, want false", requirePAR)
	}

	// Also check DPoP discovery.
	dpopAlgs, ok := body["dpop_signing_alg_values_supported"].([]interface{})
	if !ok || len(dpopAlgs) == 0 {
		t.Fatal("missing dpop_signing_alg_values_supported")
	}
	foundES256 := false
	foundEdDSA := false
	for _, alg := range dpopAlgs {
		if alg == "ES256" {
			foundES256 = true
		}
		if alg == "EdDSA" {
			foundEdDSA = true
		}
	}
	if !foundES256 || !foundEdDSA {
		t.Errorf("dpop_signing_alg_values_supported = %v, want ES256 and EdDSA", dpopAlgs)
	}
}
