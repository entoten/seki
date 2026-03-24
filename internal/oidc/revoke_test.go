package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

func (h *introspectHarness) doRevoke(t *testing.T, params url.Values, basicAuth ...string) *http.Response {
	t.Helper()
	body := params.Encode()
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basicAuth) == 2 {
		req.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func TestRevoke_RefreshToken_Succeeds(t *testing.T) {
	h := newIntrospectHarness(t)

	rawToken := "revoke-test-refresh-token"
	hash := hashForTest(rawToken)
	now := time.Now().UTC()

	rt := &storage.RefreshToken{
		ID:        "rt-revoke-1",
		TokenHash: hash,
		ClientID:  "test-client",
		UserID:    "user-1",
		Scopes:    []string{"openid"},
		Family:    "family-revoke-1",
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := h.store.CreateRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	// Revoke the token.
	params := url.Values{
		"token":           {rawToken},
		"token_type_hint": {"refresh_token"},
	}
	resp := h.doRevoke(t, params, "test-client", "test-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Introspect should now return inactive.
	introspectParams := url.Values{
		"token":           {rawToken},
		"token_type_hint": {"refresh_token"},
	}
	introspectResp := h.doIntrospect(t, introspectParams, "test-client", "test-secret")
	defer introspectResp.Body.Close()

	body := decodeIntrospectResponse(t, introspectResp)
	if body["active"] != false {
		t.Fatalf("expected active=false after revocation, got %v", body["active"])
	}
}

func TestRevoke_AccessToken_Returns200(t *testing.T) {
	h := newIntrospectHarness(t)

	// Generate a valid JWT access token.
	now := time.Now().UTC()
	claims := map[string]interface{}{
		"sub":   "user-1",
		"aud":   "test-client",
		"scope": "openid",
		"iat":   now.Unix(),
		"exp":   now.Add(15 * time.Minute).Unix(),
		"iss":   "https://auth.example.com",
		"typ":   "access_token",
	}
	token, err := h.signer.Sign(claims)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	// Revoking a JWT access token is a no-op but should return 200.
	params := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}
	resp := h.doRevoke(t, params, "test-client", "test-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestRevoke_InvalidToken_Returns200(t *testing.T) {
	h := newIntrospectHarness(t)

	// Per RFC 7009, revoking an invalid/unknown token should return 200.
	params := url.Values{
		"token": {"completely-unknown-token-value"},
	}
	resp := h.doRevoke(t, params, "test-client", "test-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for invalid token (spec compliance), got %d", resp.StatusCode)
	}
}

func TestRevoke_UnauthenticatedCaller_Returns401(t *testing.T) {
	h := newIntrospectHarness(t)

	params := url.Values{
		"token": {"some-token"},
	}
	// No basic auth credentials.
	resp := h.doRevoke(t, params)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}
