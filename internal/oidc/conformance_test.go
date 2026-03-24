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

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

// conformanceHarness provides a fully wired OIDC provider for end-to-end
// conformance testing. It includes a storage backend, session manager, signer,
// test user, and both confidential and public OAuth 2 clients.
type conformanceHarness struct {
	store    storage.Storage
	sessions *session.Manager
	provider *oidc.Provider
	mux      *http.ServeMux
	signer   crypto.Signer
	cookie   *http.Cookie
}

func newConformanceHarness(t *testing.T) *conformanceHarness {
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

	// Create a test user with profile and email data.
	err = store.CreateUser(ctx, &storage.User{
		ID:          "user-1",
		Email:       "conformance@example.com",
		DisplayName: "Conformance User",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create a confidential client (has secret, supports auth_code + refresh).
	hasher := crypto.NewBcryptHasher(4)
	secretHash, err := hasher.Hash("conf-secret")
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	err = store.CreateClient(ctx, &storage.Client{
		ID:           "conf-client",
		Name:         "Conformance Confidential Client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"https://rp.example.com/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		PKCERequired: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create confidential client: %v", err)
	}

	// Create a public client (no secret, PKCE required).
	err = store.CreateClient(ctx, &storage.Client{
		ID:           "pub-client",
		Name:         "Conformance Public Client",
		SecretHash:   "",
		RedirectURIs: []string{"https://spa.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "profile"},
		PKCERequired: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create public client: %v", err)
	}

	// Session manager with an active session for user-1.
	sessCfg := session.Config{CookieName: "seki_session"}
	mgr := session.NewManager(store, sessCfg)
	sess, err := mgr.Create(ctx, "user-1", "", "127.0.0.1", "ConformanceTest")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, store,
		oidc.WithSessionManager(mgr))

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &conformanceHarness{
		store:    store,
		sessions: mgr,
		provider: provider,
		mux:      mux,
		signer:   signer,
		cookie: &http.Cookie{
			Name:  "seki_session",
			Value: sess.ID,
		},
	}
}

// --- helpers ---

func (h *conformanceHarness) get(t *testing.T, path string, withCookie bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if withCookie {
		req.AddCookie(h.cookie)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func (h *conformanceHarness) post(t *testing.T, path string, form url.Values, basicAuth ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basicAuth) == 2 {
		req.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func (h *conformanceHarness) getJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	rec := h.get(t, path, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: expected 200, got %d", path, rec.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: decode: %v", path, err)
	}
	return body
}

func (h *conformanceHarness) authorize(t *testing.T, params url.Values) (code string, loc *url.URL) {
	t.Helper()
	rec := h.get(t, "/authorize?"+params.Encode(), true)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
	resp := rec.Result()
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("authorize: no Location header: %v", err)
	}
	code = loc.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize: no code in redirect; error=%s desc=%s",
			loc.Query().Get("error"), loc.Query().Get("error_description"))
	}
	return code, loc
}

func (h *conformanceHarness) exchangeCode(t *testing.T, code, verifier, clientID, clientSecret, redirectURI string) map[string]interface{} {
	t.Helper()
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	if clientSecret != "" {
		params.Set("client_secret", clientSecret)
	}
	rec := h.post(t, "/token", params)
	if rec.Code != http.StatusOK {
		var errBody map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &errBody)
		t.Fatalf("token exchange: expected 200, got %d: %v", rec.Code, errBody)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("token exchange: decode: %v", err)
	}
	return body
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// TestOIDCConformance is the main entry point that runs all OIDC conformance
// subtests covering the Basic OP and Config OP profiles.
// ---------------------------------------------------------------------------

func TestOIDCConformance(t *testing.T) {
	t.Run("Discovery", testDiscoveryConformance)
	t.Run("JWKS", testJWKSConformance)
	t.Run("AuthorizationEndpoint", testAuthorizeConformance)
	t.Run("TokenEndpoint", testTokenConformance)
	t.Run("UserInfoEndpoint", testUserInfoConformance)
	t.Run("Introspection", testIntrospectionConformance)
	t.Run("Revocation", testRevocationConformance)
	t.Run("RefreshTokenRotation", testRefreshTokenConformance)
	t.Run("OAuth21Rejections", testOAuth21Rejections)
}

// --- Discovery ---

func testDiscoveryConformance(t *testing.T) {
	h := newConformanceHarness(t)
	disco := h.getJSON(t, "/.well-known/openid-configuration")

	t.Run("RequiredFieldsPresent", func(t *testing.T) {
		required := []string{
			"issuer",
			"authorization_endpoint",
			"token_endpoint",
			"userinfo_endpoint",
			"jwks_uri",
			"scopes_supported",
			"response_types_supported",
			"grant_types_supported",
			"subject_types_supported",
			"id_token_signing_alg_values_supported",
			"token_endpoint_auth_methods_supported",
			"code_challenge_methods_supported",
			"introspection_endpoint",
			"revocation_endpoint",
		}
		for _, field := range required {
			if _, ok := disco[field]; !ok {
				t.Errorf("missing required field: %s", field)
			}
		}
	})

	t.Run("IssuerMatchesAndHasNoTrailingSlash", func(t *testing.T) {
		iss, _ := disco["issuer"].(string)
		if iss != "https://auth.example.com" {
			t.Errorf("issuer = %q, want https://auth.example.com", iss)
		}
		if strings.HasSuffix(iss, "/") {
			t.Error("issuer must not have trailing slash")
		}
	})

	t.Run("EndpointURLsAreAbsolute", func(t *testing.T) {
		endpoints := []string{
			"authorization_endpoint",
			"token_endpoint",
			"userinfo_endpoint",
			"jwks_uri",
			"introspection_endpoint",
			"revocation_endpoint",
		}
		for _, ep := range endpoints {
			val, _ := disco[ep].(string)
			if val == "" {
				t.Errorf("%s is empty", ep)
				continue
			}
			parsed, err := url.Parse(val)
			if err != nil {
				t.Errorf("%s: invalid URL: %v", ep, err)
				continue
			}
			if !parsed.IsAbs() {
				t.Errorf("%s = %q is not absolute", ep, val)
			}
		}
	})

	t.Run("ScopesSupported", func(t *testing.T) {
		scopes, _ := disco["scopes_supported"].([]interface{})
		found := map[string]bool{}
		for _, s := range scopes {
			found[s.(string)] = true
		}
		for _, want := range []string{"openid", "profile", "email"} {
			if !found[want] {
				t.Errorf("scopes_supported missing %q", want)
			}
		}
	})

	t.Run("ResponseTypesOnlyCode", func(t *testing.T) {
		rts, _ := disco["response_types_supported"].([]interface{})
		if len(rts) != 1 || rts[0] != "code" {
			t.Errorf("response_types_supported = %v, want [code]", rts)
		}
	})

	t.Run("GrantTypesExcludeImplicitAndROPC", func(t *testing.T) {
		gts, _ := disco["grant_types_supported"].([]interface{})
		for _, g := range gts {
			gs := g.(string)
			if gs == "implicit" {
				t.Error("grant_types_supported must not include implicit")
			}
			if gs == "password" {
				t.Error("grant_types_supported must not include password (ROPC)")
			}
		}
		need := map[string]bool{"authorization_code": false, "refresh_token": false}
		for _, g := range gts {
			if _, ok := need[g.(string)]; ok {
				need[g.(string)] = true
			}
		}
		for g, found := range need {
			if !found {
				t.Errorf("grant_types_supported missing %q", g)
			}
		}
	})

	t.Run("SigningAlgorithmPresent", func(t *testing.T) {
		algs, _ := disco["id_token_signing_alg_values_supported"].([]interface{})
		if len(algs) == 0 {
			t.Fatal("id_token_signing_alg_values_supported is empty")
		}
		if algs[0] != "EdDSA" {
			t.Errorf("first signing alg = %v, want EdDSA", algs[0])
		}
	})

	t.Run("CodeChallengeMethodsS256", func(t *testing.T) {
		methods, _ := disco["code_challenge_methods_supported"].([]interface{})
		found := false
		for _, m := range methods {
			if m == "S256" {
				found = true
			}
		}
		if !found {
			t.Error("code_challenge_methods_supported must include S256")
		}
	})
}

// --- JWKS ---

func testJWKSConformance(t *testing.T) {
	h := newConformanceHarness(t)
	jwks := h.getJSON(t, "/.well-known/jwks.json")

	t.Run("HasKeysArray", func(t *testing.T) {
		keys, ok := jwks["keys"].([]interface{})
		if !ok || len(keys) == 0 {
			t.Fatal("keys field missing or empty")
		}
	})

	t.Run("KeyHasRequiredFields", func(t *testing.T) {
		keys := jwks["keys"].([]interface{})
		key := keys[0].(map[string]interface{})
		for _, field := range []string{"kty", "use", "kid", "alg"} {
			if key[field] == nil || key[field] == "" {
				t.Errorf("JWK missing required field: %s", field)
			}
		}
	})

	t.Run("KeyTypeAndAlgorithm", func(t *testing.T) {
		keys := jwks["keys"].([]interface{})
		key := keys[0].(map[string]interface{})
		if key["kty"] != "OKP" {
			t.Errorf("kty = %v, want OKP", key["kty"])
		}
		if key["alg"] != "EdDSA" {
			t.Errorf("alg = %v, want EdDSA", key["alg"])
		}
		if key["use"] != "sig" {
			t.Errorf("use = %v, want sig", key["use"])
		}
	})

	t.Run("CacheControlHeader", func(t *testing.T) {
		rec := h.get(t, "/.well-known/jwks.json", false)
		cc := rec.Header().Get("Cache-Control")
		if !strings.Contains(cc, "max-age=") {
			t.Errorf("Cache-Control = %q, expected max-age directive", cc)
		}
	})
}

// --- Authorization Endpoint ---

func testAuthorizeConformance(t *testing.T) {
	verifier := "conformance-verifier-value-32chars-ok"
	challenge := pkceChallenge(verifier)

	t.Run("ValidRequestReturnsCode", func(t *testing.T) {
		h := newConformanceHarness(t)
		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid profile email"},
			"state":                 {"test-state-123"},
			"nonce":                 {"nonce-abc"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		code, loc := h.authorize(t, params)
		if code == "" {
			t.Fatal("expected authorization code")
		}
		if loc.Query().Get("state") != "test-state-123" {
			t.Errorf("state = %q, want test-state-123", loc.Query().Get("state"))
		}
	})

	t.Run("MissingClientIDReturnsError", func(t *testing.T) {
		h := newConformanceHarness(t)
		rec := h.get(t, "/authorize?redirect_uri=https://rp.example.com/callback&response_type=code&scope=openid", true)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("MissingResponseTypeRedirectsWithError", func(t *testing.T) {
		h := newConformanceHarness(t)
		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"scope":                 {"openid"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		rec := h.get(t, "/authorize?"+params.Encode(), true)
		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rec.Code)
		}
		resp := rec.Result()
		loc, _ := resp.Location()
		if loc.Query().Get("error") != "invalid_request" {
			t.Errorf("error = %q, want invalid_request", loc.Query().Get("error"))
		}
	})

	t.Run("UnsupportedResponseTypeReturnsError", func(t *testing.T) {
		h := newConformanceHarness(t)
		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"token"},
			"scope":                 {"openid"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		rec := h.get(t, "/authorize?"+params.Encode(), true)
		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rec.Code)
		}
		resp := rec.Result()
		loc, _ := resp.Location()
		if loc.Query().Get("error") != "unsupported_response_type" {
			t.Errorf("error = %q, want unsupported_response_type", loc.Query().Get("error"))
		}
	})

	t.Run("MissingScopeOpenIDReturnsError", func(t *testing.T) {
		h := newConformanceHarness(t)
		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"profile"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		rec := h.get(t, "/authorize?"+params.Encode(), true)
		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rec.Code)
		}
		resp := rec.Result()
		loc, _ := resp.Location()
		if loc.Query().Get("error") != "invalid_scope" {
			t.Errorf("error = %q, want invalid_scope", loc.Query().Get("error"))
		}
	})

	t.Run("InvalidRedirectURINotRedirected", func(t *testing.T) {
		h := newConformanceHarness(t)
		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://evil.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		rec := h.get(t, "/authorize?"+params.Encode(), true)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("MissingPKCEReturnsError", func(t *testing.T) {
		h := newConformanceHarness(t)
		params := url.Values{
			"client_id":     {"conf-client"},
			"redirect_uri":  {"https://rp.example.com/callback"},
			"response_type": {"code"},
			"scope":         {"openid"},
		}
		rec := h.get(t, "/authorize?"+params.Encode(), true)
		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rec.Code)
		}
		resp := rec.Result()
		loc, _ := resp.Location()
		if loc.Query().Get("error") != "invalid_request" {
			t.Errorf("error = %q, want invalid_request", loc.Query().Get("error"))
		}
	})
}

// --- Token Endpoint ---

func testTokenConformance(t *testing.T) {
	verifier := "token-conformance-verifier-val32"
	challenge := pkceChallenge(verifier)

	t.Run("AuthCodeExchangeReturnsAllTokens", func(t *testing.T) {
		h := newConformanceHarness(t)

		// Authorize first to get a code.
		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid profile email"},
			"state":                 {"s1"},
			"nonce":                 {"n1"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		code, _ := h.authorize(t, params)
		tokens := h.exchangeCode(t, code, verifier, "conf-client", "conf-secret", "https://rp.example.com/callback")

		// All three token types must be present.
		if tokens["access_token"] == nil || tokens["access_token"] == "" {
			t.Error("missing access_token")
		}
		if tokens["id_token"] == nil || tokens["id_token"] == "" {
			t.Error("missing id_token")
		}
		if tokens["refresh_token"] == nil || tokens["refresh_token"] == "" {
			t.Error("missing refresh_token")
		}
		if tokens["token_type"] != "Bearer" {
			t.Errorf("token_type = %v, want Bearer", tokens["token_type"])
		}
		if tokens["expires_in"] != float64(900) {
			t.Errorf("expires_in = %v, want 900", tokens["expires_in"])
		}
	})

	t.Run("IDTokenHasRequiredClaims", func(t *testing.T) {
		h := newConformanceHarness(t)

		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid profile email"},
			"nonce":                 {"nonce-id-test"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		code, _ := h.authorize(t, params)
		tokens := h.exchangeCode(t, code, verifier, "conf-client", "conf-secret", "https://rp.example.com/callback")

		idTokenStr, _ := tokens["id_token"].(string)
		idClaims, err := h.signer.Verify(idTokenStr)
		if err != nil {
			t.Fatalf("verify id_token: %v", err)
		}

		// OIDC Core 1.0 section 2: required ID Token claims.
		for _, claim := range []string{"iss", "sub", "aud", "exp", "iat"} {
			if idClaims[claim] == nil {
				t.Errorf("id_token missing required claim: %s", claim)
			}
		}
		if idClaims["iss"] != "https://auth.example.com" {
			t.Errorf("id_token iss = %v, want https://auth.example.com", idClaims["iss"])
		}
		if idClaims["sub"] != "user-1" {
			t.Errorf("id_token sub = %v, want user-1", idClaims["sub"])
		}
		if idClaims["aud"] != "conf-client" {
			t.Errorf("id_token aud = %v, want conf-client", idClaims["aud"])
		}
		if idClaims["nonce"] != "nonce-id-test" {
			t.Errorf("id_token nonce = %v, want nonce-id-test", idClaims["nonce"])
		}

		// Profile and email claims.
		if idClaims["email"] != "conformance@example.com" {
			t.Errorf("id_token email = %v, want conformance@example.com", idClaims["email"])
		}
		if idClaims["name"] != "Conformance User" {
			t.Errorf("id_token name = %v, want Conformance User", idClaims["name"])
		}
	})

	t.Run("AccessTokenIsValidJWT", func(t *testing.T) {
		h := newConformanceHarness(t)

		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid profile"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		code, _ := h.authorize(t, params)
		tokens := h.exchangeCode(t, code, verifier, "conf-client", "conf-secret", "https://rp.example.com/callback")

		atStr, _ := tokens["access_token"].(string)
		atClaims, err := h.signer.Verify(atStr)
		if err != nil {
			t.Fatalf("verify access_token: %v", err)
		}
		if atClaims["sub"] != "user-1" {
			t.Errorf("access_token sub = %v, want user-1", atClaims["sub"])
		}
		if atClaims["iss"] != "https://auth.example.com" {
			t.Errorf("access_token iss = %v, want https://auth.example.com", atClaims["iss"])
		}
		if atClaims["client_id"] != "conf-client" {
			t.Errorf("access_token client_id = %v, want conf-client", atClaims["client_id"])
		}
		if atClaims["jti"] == nil || atClaims["jti"] == "" {
			t.Error("access_token missing jti claim")
		}
		// Verify JWT header typ is at+jwt (RFC 9068).
		atHeader := decodeJWTHeader(t, atStr)
		if atHeader["typ"] != "at+jwt" {
			t.Errorf("access_token header typ = %v, want at+jwt", atHeader["typ"])
		}
	})

	t.Run("AuthCodeSingleUse", func(t *testing.T) {
		h := newConformanceHarness(t)

		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		code, _ := h.authorize(t, params)

		// First exchange succeeds.
		_ = h.exchangeCode(t, code, verifier, "conf-client", "conf-secret", "https://rp.example.com/callback")

		// Second exchange must fail.
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://rp.example.com/callback"},
			"client_id":     {"conf-client"},
			"client_secret": {"conf-secret"},
			"code_verifier": {verifier},
		}
		rec := h.post(t, "/token", form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 on second code use, got %d", rec.Code)
		}
	})

	t.Run("WrongPKCEVerifierFails", func(t *testing.T) {
		h := newConformanceHarness(t)

		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		code, _ := h.authorize(t, params)

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://rp.example.com/callback"},
			"client_id":     {"conf-client"},
			"client_secret": {"conf-secret"},
			"code_verifier": {"wrong-verifier-value"},
		}
		rec := h.post(t, "/token", form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for wrong PKCE verifier, got %d", rec.Code)
		}
		var body map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body["error"] != "invalid_grant" {
			t.Errorf("error = %v, want invalid_grant", body["error"])
		}
	})

	t.Run("PublicClientAuthCodeExchange", func(t *testing.T) {
		h := newConformanceHarness(t)

		pubVerifier := "public-client-pkce-verifier-val32"
		pubChallenge := pkceChallenge(pubVerifier)

		params := url.Values{
			"client_id":             {"pub-client"},
			"redirect_uri":          {"https://spa.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid profile"},
			"code_challenge":        {pubChallenge},
			"code_challenge_method": {"S256"},
		}
		code, _ := h.authorize(t, params)

		// Public client: no secret, just PKCE.
		tokens := h.exchangeCode(t, code, pubVerifier, "pub-client", "", "https://spa.example.com/callback")
		if tokens["access_token"] == nil || tokens["access_token"] == "" {
			t.Error("missing access_token for public client")
		}
	})
}

// --- UserInfo Endpoint ---

func testUserInfoConformance(t *testing.T) {
	t.Run("ReturnsClaimsMatchingIDToken", func(t *testing.T) {
		h := newConformanceHarness(t)

		verifier := "userinfo-conformance-verifier-32"
		challenge := pkceChallenge(verifier)

		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid profile email"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		code, _ := h.authorize(t, params)
		tokens := h.exchangeCode(t, code, verifier, "conf-client", "conf-secret", "https://rp.example.com/callback")

		accessToken, _ := tokens["access_token"].(string)

		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var userinfo map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &userinfo); err != nil {
			t.Fatalf("decode userinfo: %v", err)
		}

		// sub must match the ID token.
		if userinfo["sub"] != "user-1" {
			t.Errorf("userinfo sub = %v, want user-1", userinfo["sub"])
		}
		if userinfo["email"] != "conformance@example.com" {
			t.Errorf("userinfo email = %v, want conformance@example.com", userinfo["email"])
		}
		if userinfo["name"] != "Conformance User" {
			t.Errorf("userinfo name = %v, want Conformance User", userinfo["name"])
		}
	})

	t.Run("MissingBearerTokenReturns401", func(t *testing.T) {
		h := newConformanceHarness(t)
		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("InvalidBearerTokenReturns401", func(t *testing.T) {
		h := newConformanceHarness(t)
		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		req.Header.Set("Authorization", "Bearer invalid.jwt.garbage")
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})
}

// --- Introspection ---

func testIntrospectionConformance(t *testing.T) {
	t.Run("ActiveTokenReturnsMetadata", func(t *testing.T) {
		h := newConformanceHarness(t)

		verifier := "introspect-conformance-verif-32c"
		challenge := pkceChallenge(verifier)

		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid profile"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		code, _ := h.authorize(t, params)
		tokens := h.exchangeCode(t, code, verifier, "conf-client", "conf-secret", "https://rp.example.com/callback")

		accessToken, _ := tokens["access_token"].(string)

		form := url.Values{"token": {accessToken}}
		rec := h.post(t, "/introspect", form, "conf-client", "conf-secret")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		var body map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)

		if body["active"] != true {
			t.Fatalf("expected active=true, got %v", body["active"])
		}
		if body["sub"] != "user-1" {
			t.Errorf("sub = %v, want user-1", body["sub"])
		}
		if body["token_type"] != "Bearer" {
			t.Errorf("token_type = %v, want Bearer", body["token_type"])
		}
	})

	t.Run("InvalidTokenReturnsInactive", func(t *testing.T) {
		h := newConformanceHarness(t)
		form := url.Values{"token": {"not-a-valid-token"}}
		rec := h.post(t, "/introspect", form, "conf-client", "conf-secret")
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		var body map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body["active"] != false {
			t.Errorf("expected active=false, got %v", body["active"])
		}
	})

	t.Run("UnauthenticatedCallerReturns401", func(t *testing.T) {
		h := newConformanceHarness(t)
		form := url.Values{"token": {"anything"}}
		rec := h.post(t, "/introspect", form)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})
}

// --- Revocation ---

func testRevocationConformance(t *testing.T) {
	t.Run("RevokedRefreshTokenBecomesInactive", func(t *testing.T) {
		h := newConformanceHarness(t)

		verifier := "revoke-conformance-verifier-32ch"
		challenge := pkceChallenge(verifier)

		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		code, _ := h.authorize(t, params)
		tokens := h.exchangeCode(t, code, verifier, "conf-client", "conf-secret", "https://rp.example.com/callback")

		refreshToken, _ := tokens["refresh_token"].(string)

		// Revoke the refresh token.
		revokeForm := url.Values{
			"token":           {refreshToken},
			"token_type_hint": {"refresh_token"},
		}
		rec := h.post(t, "/revoke", revokeForm, "conf-client", "conf-secret")
		if rec.Code != http.StatusOK {
			t.Fatalf("revoke: expected 200, got %d", rec.Code)
		}

		// Introspect: must be inactive.
		introspectForm := url.Values{
			"token":           {refreshToken},
			"token_type_hint": {"refresh_token"},
		}
		rec2 := h.post(t, "/introspect", introspectForm, "conf-client", "conf-secret")
		if rec2.Code != http.StatusOK {
			t.Fatalf("introspect: expected 200, got %d", rec2.Code)
		}
		var body map[string]interface{}
		_ = json.Unmarshal(rec2.Body.Bytes(), &body)
		if body["active"] != false {
			t.Errorf("expected active=false after revocation, got %v", body["active"])
		}
	})

	t.Run("RevokingUnknownTokenReturns200", func(t *testing.T) {
		h := newConformanceHarness(t)
		form := url.Values{"token": {"unknown-token-value"}}
		rec := h.post(t, "/revoke", form, "conf-client", "conf-secret")
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 for unknown token (RFC 7009), got %d", rec.Code)
		}
	})
}

// --- Refresh Token Rotation ---

func testRefreshTokenConformance(t *testing.T) {
	t.Run("RotationIssuesNewRefreshToken", func(t *testing.T) {
		h := newConformanceHarness(t)

		verifier := "refresh-conformance-verifier-32c"
		challenge := pkceChallenge(verifier)

		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid profile"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		code, _ := h.authorize(t, params)
		tokens := h.exchangeCode(t, code, verifier, "conf-client", "conf-secret", "https://rp.example.com/callback")

		oldRefresh, _ := tokens["refresh_token"].(string)

		// Refresh.
		refreshForm := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {oldRefresh},
			"client_id":     {"conf-client"},
			"client_secret": {"conf-secret"},
		}
		rec := h.post(t, "/token", refreshForm)
		if rec.Code != http.StatusOK {
			var errBody map[string]interface{}
			_ = json.Unmarshal(rec.Body.Bytes(), &errBody)
			t.Fatalf("refresh: expected 200, got %d: %v", rec.Code, errBody)
		}

		var newTokens map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &newTokens)

		newRefresh, _ := newTokens["refresh_token"].(string)
		if newRefresh == "" {
			t.Fatal("refresh response missing refresh_token")
		}
		if newRefresh == oldRefresh {
			t.Error("rotated refresh_token must differ from original")
		}
		if newTokens["access_token"] == nil || newTokens["access_token"] == "" {
			t.Error("refresh response missing access_token")
		}
		if newTokens["id_token"] == nil || newTokens["id_token"] == "" {
			t.Error("refresh response missing id_token")
		}
	})

	t.Run("OldRefreshTokenInvalidatedAfterRotation", func(t *testing.T) {
		h := newConformanceHarness(t)

		verifier := "rotation-invalidate-verifier-32c"
		challenge := pkceChallenge(verifier)

		params := url.Values{
			"client_id":             {"conf-client"},
			"redirect_uri":          {"https://rp.example.com/callback"},
			"response_type":         {"code"},
			"scope":                 {"openid"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		code, _ := h.authorize(t, params)
		tokens := h.exchangeCode(t, code, verifier, "conf-client", "conf-secret", "https://rp.example.com/callback")

		oldRefresh, _ := tokens["refresh_token"].(string)

		// Rotate once.
		refreshForm := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {oldRefresh},
			"client_id":     {"conf-client"},
			"client_secret": {"conf-secret"},
		}
		rec := h.post(t, "/token", refreshForm)
		if rec.Code != http.StatusOK {
			t.Fatalf("refresh: expected 200, got %d", rec.Code)
		}

		// Reuse old token -- must fail (theft detection).
		rec2 := h.post(t, "/token", refreshForm)
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 on old refresh token reuse, got %d", rec2.Code)
		}
		var body map[string]interface{}
		_ = json.Unmarshal(rec2.Body.Bytes(), &body)
		if body["error"] != "invalid_grant" {
			t.Errorf("error = %v, want invalid_grant", body["error"])
		}
	})
}

// --- OAuth 2.1 Rejections ---

func testOAuth21Rejections(t *testing.T) {
	t.Run("ImplicitGrantRejected", func(t *testing.T) {
		h := newConformanceHarness(t)
		challenge := pkceChallenge("dummy-verifier-for-implicit-test")
		params := url.Values{
			"client_id":             {"pub-client"},
			"redirect_uri":          {"https://spa.example.com/callback"},
			"response_type":         {"token"},
			"scope":                 {"openid"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		rec := h.get(t, "/authorize?"+params.Encode(), true)
		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rec.Code)
		}
		resp := rec.Result()
		loc, _ := resp.Location()
		if loc.Query().Get("error") != "unsupported_response_type" {
			t.Errorf("error = %q, want unsupported_response_type", loc.Query().Get("error"))
		}
	})

	t.Run("ROPCGrantRejected", func(t *testing.T) {
		h := newConformanceHarness(t)
		form := url.Values{
			"grant_type": {"password"},
			"username":   {"conformance@example.com"},
			"password":   {"password123"},
			"client_id":  {"conf-client"},
		}
		rec := h.post(t, "/token", form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
		var body map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body["error"] != "unsupported_grant_type" {
			t.Errorf("error = %v, want unsupported_grant_type", body["error"])
		}
	})
}

// decodeJWTHeader decodes the header portion of a JWT without verification.
func decodeJWTHeader(t *testing.T, tokenStr string) map[string]interface{} {
	t.Helper()
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) < 2 {
		t.Fatalf("invalid JWT: expected at least 2 parts, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal JWT header: %v", err)
	}
	return header
}
