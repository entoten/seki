package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/oidc"
	"github.com/entoten/seki/internal/storage"
	"github.com/golang-jwt/jwt/v5"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

// dpopHarness is a test harness for DPoP tests.
type dpopHarness struct {
	store    storage.Storage
	provider *oidc.Provider
	mux      *http.ServeMux
	signer   crypto.Signer
}

func newDPoPHarness(t *testing.T) *dpopHarness {
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
		GrantTypes:   []string{"authorization_code", "client_credentials", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email"},
		PKCERequired: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	signer := newTestSigner(t)
	provider := oidc.NewProvider("https://auth.example.com", signer, store)

	mux := http.NewServeMux()
	provider.RegisterRoutes(mux)

	return &dpopHarness{
		store:    store,
		provider: provider,
		mux:      mux,
		signer:   signer,
	}
}

// createDPoPProof creates a DPoP proof JWT signed with the given EC key.
func createDPoPProof(t *testing.T, key *ecdsa.PrivateKey, method, uri string, opts ...func(map[string]interface{}, map[string]interface{})) string {
	t.Helper()

	// Build JWK for the public key.
	pub := key.PublicKey
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	// Pad to 32 bytes for P-256.
	for len(xBytes) < 32 {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < 32 {
		yBytes = append([]byte{0}, yBytes...)
	}

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"htm": method,
		"htu": uri,
		"jti": fmt.Sprintf("dpop-jti-%d", now.UnixNano()),
		"iat": now.Unix(),
	}

	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": jwk,
	}

	// Allow overrides.
	for _, opt := range opts {
		opt(header, claims)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	// Set custom headers.
	for k, v := range header {
		if k != "alg" {
			token.Header[k] = v
		}
	}

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign dpop proof: %v", err)
	}
	return signed
}

func (h *dpopHarness) doTokenRequestWithDPoP(t *testing.T, params url.Values, dpopProof string, basicAuth ...string) *http.Response {
	t.Helper()
	body := params.Encode()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpopProof != "" {
		req.Header.Set("DPoP", dpopProof)
	}
	if len(basicAuth) == 2 {
		req.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func TestDPoP_TokenRequestWithValidProof_GetsDPoPBoundToken(t *testing.T) {
	h := newDPoPHarness(t)

	// Generate an EC key for DPoP.
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	// Create an auth code.
	verifier := "dpop-test-verifier-value"
	challenge := computeS256Challenge(verifier)
	now := time.Now().UTC()

	ac := &storage.AuthCode{
		Code:                "dpop-code-1",
		ClientID:            "test-client",
		UserID:              "user-1",
		RedirectURI:         "https://app.example.com/callback",
		Scopes:              []string{"openid", "profile"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(10 * time.Minute),
		CreatedAt:           now,
	}
	if err := h.store.CreateAuthCode(context.Background(), ac); err != nil {
		t.Fatalf("create auth code: %v", err)
	}

	proof := createDPoPProof(t, dpopKey, "POST", "https://auth.example.com/token")

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"dpop-code-1"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
	}

	resp := h.doTokenRequestWithDPoP(t, params, proof, "test-client", "test-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)

	// token_type should be DPoP.
	if body["token_type"] != "DPoP" {
		t.Errorf("token_type = %v, want DPoP", body["token_type"])
	}

	// Access token should have cnf.jkt claim.
	accessTokenStr, ok := body["access_token"].(string)
	if !ok || accessTokenStr == "" {
		t.Fatal("missing access_token")
	}

	claims, err := h.signer.Verify(accessTokenStr)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}

	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		t.Fatal("access token missing cnf claim")
	}
	jkt, ok := cnf["jkt"].(string)
	if !ok || jkt == "" {
		t.Fatal("cnf missing jkt")
	}
}

func TestDPoP_TokenRequestWithoutDPoP_GetsBearerToken(t *testing.T) {
	h := newDPoPHarness(t)

	verifier := "no-dpop-verifier"
	challenge := computeS256Challenge(verifier)
	now := time.Now().UTC()

	ac := &storage.AuthCode{
		Code:                "no-dpop-code",
		ClientID:            "test-client",
		UserID:              "user-1",
		RedirectURI:         "https://app.example.com/callback",
		Scopes:              []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(10 * time.Minute),
		CreatedAt:           now,
	}
	if err := h.store.CreateAuthCode(context.Background(), ac); err != nil {
		t.Fatalf("create auth code: %v", err)
	}

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"no-dpop-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
	}

	resp := h.doTokenRequestWithDPoP(t, params, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)

	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", body["token_type"])
	}

	// Access token should NOT have cnf claim.
	accessTokenStr := body["access_token"].(string)
	claims, err := h.signer.Verify(accessTokenStr)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if _, ok := claims["cnf"]; ok {
		t.Error("Bearer access token should not have cnf claim")
	}
}

func TestDPoP_InvalidProof_Rejected(t *testing.T) {
	h := newDPoPHarness(t)

	verifier := "invalid-dpop-verifier"
	challenge := computeS256Challenge(verifier)
	now := time.Now().UTC()

	ac := &storage.AuthCode{
		Code:                "invalid-dpop-code",
		ClientID:            "test-client",
		UserID:              "user-1",
		RedirectURI:         "https://app.example.com/callback",
		Scopes:              []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(10 * time.Minute),
		CreatedAt:           now,
	}
	if err := h.store.CreateAuthCode(context.Background(), ac); err != nil {
		t.Fatalf("create auth code: %v", err)
	}

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"invalid-dpop-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
	}

	// Send an invalid DPoP proof (just garbage).
	resp := h.doTokenRequestWithDPoP(t, params, "this.is.not.a.valid.dpop.proof")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_dpop_proof" {
		t.Errorf("error = %v, want invalid_dpop_proof", body["error"])
	}
}

func TestDPoP_CNFJKTMatchesDPoPKey(t *testing.T) {
	h := newDPoPHarness(t)

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	verifier := "cnf-jkt-verifier"
	challenge := computeS256Challenge(verifier)
	now := time.Now().UTC()

	ac := &storage.AuthCode{
		Code:                "cnf-jkt-code",
		ClientID:            "test-client",
		UserID:              "user-1",
		RedirectURI:         "https://app.example.com/callback",
		Scopes:              []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(10 * time.Minute),
		CreatedAt:           now,
	}
	if err := h.store.CreateAuthCode(context.Background(), ac); err != nil {
		t.Fatalf("create auth code: %v", err)
	}

	proof := createDPoPProof(t, dpopKey, "POST", "https://auth.example.com/token")

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"cnf-jkt-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
	}

	resp := h.doTokenRequestWithDPoP(t, params, proof)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)
	accessTokenStr := body["access_token"].(string)
	claims, err := h.signer.Verify(accessTokenStr)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}

	cnf := claims["cnf"].(map[string]interface{})
	jkt := cnf["jkt"].(string)

	// Compute expected JKT from the DPoP key.
	expectedJKT := computeExpectedJKT(t, dpopKey)

	if jkt != expectedJKT {
		t.Errorf("jkt = %s, want %s", jkt, expectedJKT)
	}
}

func TestDPoP_IntrospectionIncludesCNF(t *testing.T) {
	h := newDPoPHarness(t)

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	verifier := "introspect-dpop-verifier"
	challenge := computeS256Challenge(verifier)
	now := time.Now().UTC()

	ac := &storage.AuthCode{
		Code:                "introspect-dpop-code",
		ClientID:            "test-client",
		UserID:              "user-1",
		RedirectURI:         "https://app.example.com/callback",
		Scopes:              []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(10 * time.Minute),
		CreatedAt:           now,
	}
	if err := h.store.CreateAuthCode(context.Background(), ac); err != nil {
		t.Fatalf("create auth code: %v", err)
	}

	proof := createDPoPProof(t, dpopKey, "POST", "https://auth.example.com/token")

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"introspect-dpop-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
	}

	resp := h.doTokenRequestWithDPoP(t, params, proof)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	tokenBody := decodeTokenResponse(t, resp)
	accessToken := tokenBody["access_token"].(string)

	// Now introspect the DPoP-bound token.
	introspectParams := url.Values{
		"token": {accessToken},
	}
	introspectBody := introspectParams.Encode()
	introspectReq := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(introspectBody))
	introspectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introspectReq.SetBasicAuth("test-client", "test-secret")

	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, introspectReq)
	introspectResp := rec.Result()
	defer introspectResp.Body.Close()

	if introspectResp.StatusCode != http.StatusOK {
		t.Fatalf("introspect expected 200, got %d", introspectResp.StatusCode)
	}

	var introspectResult map[string]interface{}
	if err := json.NewDecoder(introspectResp.Body).Decode(&introspectResult); err != nil {
		t.Fatalf("decode introspect response: %v", err)
	}

	if introspectResult["active"] != true {
		t.Fatal("expected active=true")
	}

	if introspectResult["token_type"] != "DPoP" {
		t.Errorf("token_type = %v, want DPoP", introspectResult["token_type"])
	}

	cnf, ok := introspectResult["cnf"].(map[string]interface{})
	if !ok {
		t.Fatal("introspection response missing cnf")
	}
	if _, ok := cnf["jkt"].(string); !ok {
		t.Fatal("cnf missing jkt in introspection response")
	}
}

func TestDPoP_WrongHTM_Rejected(t *testing.T) {
	h := newDPoPHarness(t)

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	verifier := "wrong-htm-verifier"
	challenge := computeS256Challenge(verifier)
	now := time.Now().UTC()

	ac := &storage.AuthCode{
		Code:                "wrong-htm-code",
		ClientID:            "test-client",
		UserID:              "user-1",
		RedirectURI:         "https://app.example.com/callback",
		Scopes:              []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(10 * time.Minute),
		CreatedAt:           now,
	}
	if err := h.store.CreateAuthCode(context.Background(), ac); err != nil {
		t.Fatalf("create auth code: %v", err)
	}

	// Create proof with wrong HTTP method (GET instead of POST).
	proof := createDPoPProof(t, dpopKey, "GET", "https://auth.example.com/token")

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"wrong-htm-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {verifier},
	}

	resp := h.doTokenRequestWithDPoP(t, params, proof)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_dpop_proof" {
		t.Errorf("error = %v, want invalid_dpop_proof", body["error"])
	}
}

// computeExpectedJKT computes the expected JWK thumbprint for an EC P-256 key.
func computeExpectedJKT(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	pub := key.PublicKey
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	for len(xBytes) < 32 {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < 32 {
		yBytes = append([]byte{0}, yBytes...)
	}

	canonical, err := json.Marshal(map[string]interface{}{
		"crv": "P-256",
		"kty": "EC",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	})
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}

	hash := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
