package oidc_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/entoten/seki/internal/crypto"
	"github.com/entoten/seki/internal/storage"

	_ "github.com/entoten/seki/internal/storage/sqlite"
)

// tokenExchangeHarness builds on tokenHarness adding a client authorized for token-exchange.
type tokenExchangeHarness struct {
	*tokenHarness
}

func newTokenExchangeHarness(t *testing.T) *tokenExchangeHarness {
	t.Helper()
	th := newTokenHarness(t)

	// Create a client authorized for token-exchange.
	hasher := crypto.NewBcryptHasher(4)
	secretHash, err := hasher.Hash("te-secret")
	if err != nil {
		t.Fatalf("hash te-secret: %v", err)
	}

	now := time.Now().UTC()
	err = th.store.CreateClient(context.Background(), &storage.Client{
		ID:           "te-client",
		Name:         "Token Exchange Client",
		SecretHash:   secretHash,
		RedirectURIs: nil,
		GrantTypes:   []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
		Scopes:       []string{"openid", "profile", "email"},
		PKCERequired: false,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create te-client: %v", err)
	}

	return &tokenExchangeHarness{tokenHarness: th}
}

// generateSubjectToken creates a valid access token for use as a subject_token.
func (h *tokenExchangeHarness) generateSubjectToken(t *testing.T, sub string, scopes []string) string {
	t.Helper()
	now := time.Now().UTC()
	token, err := h.signer.Sign(map[string]interface{}{
		"sub":   sub,
		"aud":   "te-client",
		"scope": joinScopes(scopes),
		"iat":   now.Unix(),
		"exp":   now.Add(15 * time.Minute).Unix(),
		"iss":   "https://auth.example.com",
		"typ":   "access_token",
	})
	if err != nil {
		t.Fatalf("sign subject token: %v", err)
	}
	return token
}

func joinScopes(s []string) string {
	result := ""
	for i, sc := range s {
		if i > 0 {
			result += " "
		}
		result += sc
	}
	return result
}

func TestTokenExchange_ValidExchange(t *testing.T) {
	h := newTokenExchangeHarness(t)
	subjectToken := h.generateSubjectToken(t, "user-1", []string{"openid", "profile"})

	params := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"client_id":          {"te-client"},
		"client_secret":      {"te-secret"},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)
	if body["access_token"] == nil || body["access_token"] == "" {
		t.Error("missing access_token")
	}
	if body["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("issued_token_type = %v, want access_token type", body["issued_token_type"])
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", body["token_type"])
	}

	// Verify the exchanged token has the right sub.
	claims, err := h.signer.Verify(body["access_token"].(string))
	if err != nil {
		t.Fatalf("verify exchanged token: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Errorf("exchanged token sub = %v, want user-1", claims["sub"])
	}
}

func TestTokenExchange_InvalidSubjectToken(t *testing.T) {
	h := newTokenExchangeHarness(t)

	params := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {"invalid-token-value"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"client_id":          {"te-client"},
		"client_secret":      {"te-secret"},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 400, got %d: %v", resp.StatusCode, body)
	}
	body := decodeTokenResponse(t, resp)
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", body["error"])
	}
}

func TestTokenExchange_ScopedAudience(t *testing.T) {
	h := newTokenExchangeHarness(t)
	subjectToken := h.generateSubjectToken(t, "user-1", []string{"openid", "profile", "email"})

	params := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {"https://api.example.com"},
		"scope":              {"openid email"},
		"client_id":          {"te-client"},
		"client_secret":      {"te-secret"},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)
	claims, err := h.signer.Verify(body["access_token"].(string))
	if err != nil {
		t.Fatalf("verify exchanged token: %v", err)
	}
	if claims["aud"] != "https://api.example.com" {
		t.Errorf("audience = %v, want https://api.example.com", claims["aud"])
	}
	if claims["scope"] != "openid email" {
		t.Errorf("scope = %v, want 'openid email'", claims["scope"])
	}
}

func TestTokenExchange_ActorToken(t *testing.T) {
	h := newTokenExchangeHarness(t)
	subjectToken := h.generateSubjectToken(t, "user-1", []string{"openid"})

	// Create an actor token (simulating an intermediary service).
	now := time.Now().UTC()
	actorToken, err := h.signer.Sign(map[string]interface{}{
		"sub":   "service-account-1",
		"aud":   "te-client",
		"scope": "openid",
		"iat":   now.Unix(),
		"exp":   now.Add(15 * time.Minute).Unix(),
		"iss":   "https://auth.example.com",
		"typ":   "access_token",
	})
	if err != nil {
		t.Fatalf("sign actor token: %v", err)
	}

	params := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        {actorToken},
		"actor_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"client_id":          {"te-client"},
		"client_secret":      {"te-secret"},
	}

	resp := h.doTokenRequest(t, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := decodeTokenResponse(t, resp)
		t.Fatalf("expected 200, got %d: %v", resp.StatusCode, body)
	}

	body := decodeTokenResponse(t, resp)
	claims, err := h.signer.Verify(body["access_token"].(string))
	if err != nil {
		t.Fatalf("verify exchanged token: %v", err)
	}

	// Verify act claim is present.
	act, ok := claims["act"].(map[string]interface{})
	if !ok {
		t.Fatal("missing act claim in exchanged token")
	}
	if act["sub"] != "service-account-1" {
		t.Errorf("act.sub = %v, want service-account-1", act["sub"])
	}
}
