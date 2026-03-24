package oidc

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/entoten/seki/internal/storage"
	"github.com/golang-jwt/jwt/v5"
)

// authenticateClientAll authenticates the client using the method registered on
// the client, falling back to automatic detection. It supports:
//   - client_secret_basic
//   - client_secret_post
//   - private_key_jwt
//   - none (public clients)
func (p *Provider) authenticateClientAll(r *http.Request) (*storage.Client, error) {
	// Check for private_key_jwt first (client_assertion_type present).
	assertionType := r.PostFormValue("client_assertion_type")
	if assertionType != "" {
		return p.authenticatePrivateKeyJWT(r)
	}

	// Fall back to existing behaviour (Basic / post / none).
	return p.authenticateClient(r)
}

// authenticatePrivateKeyJWT verifies a client_assertion JWT per RFC 7523.
func (p *Provider) authenticatePrivateKeyJWT(r *http.Request) (*storage.Client, error) {
	assertionType := r.PostFormValue("client_assertion_type")
	if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return nil, fmt.Errorf("unsupported client_assertion_type")
	}

	assertion := r.PostFormValue("client_assertion")
	if assertion == "" {
		return nil, fmt.Errorf("missing client_assertion")
	}

	// Parse the JWT without verification to read the issuer (client_id).
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("invalid client_assertion JWT: %w", err)
	}

	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims in client_assertion")
	}

	// iss and sub must both equal the client_id.
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss == "" || iss != sub {
		return nil, fmt.Errorf("client_assertion iss and sub must be equal and non-empty")
	}

	clientID := iss

	// Look up the client.
	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		return nil, fmt.Errorf("unknown client")
	}

	// Client must be configured for private_key_jwt.
	if client.TokenEndpointAuthMethod != "private_key_jwt" {
		return nil, fmt.Errorf("client is not configured for private_key_jwt")
	}

	// Fetch the client's JWKs.
	pubKey, alg, err := p.fetchClientJWK(client)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain client JWK: %w", err)
	}

	// Verify the assertion signature.
	verifiedToken, err := jwt.Parse(assertion, func(t *jwt.Token) (interface{}, error) {
		return pubKey, nil
	}, jwt.WithValidMethods([]string{alg}))
	if err != nil {
		return nil, fmt.Errorf("client_assertion signature verification failed: %w", err)
	}

	verifiedClaims, ok := verifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type in client_assertion")
	}

	// Validate audience: must contain the token endpoint URL.
	tokenEndpoint := strings.TrimRight(p.issuer, "/") + "/token"
	if !audienceContains(verifiedClaims, tokenEndpoint) {
		return nil, fmt.Errorf("client_assertion audience does not contain token endpoint")
	}

	// Validate exp.
	expRaw, ok := verifiedClaims["exp"]
	if !ok {
		return nil, fmt.Errorf("client_assertion missing exp claim")
	}
	expFloat, ok := expRaw.(float64)
	if !ok {
		return nil, fmt.Errorf("client_assertion exp is not a number")
	}
	expTime := time.Unix(int64(expFloat), 0)
	if time.Now().After(expTime) {
		return nil, fmt.Errorf("client_assertion has expired")
	}

	return client, nil
}

// audienceContains checks whether the aud claim (string or []string) contains target.
func audienceContains(claims jwt.MapClaims, target string) bool {
	aud, ok := claims["aud"]
	if !ok {
		return false
	}
	switch v := aud.(type) {
	case string:
		return v == target
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == target {
				return true
			}
		}
	}
	return false
}

// fetchClientJWK fetches the client's public key from its registered JWKs URI.
// Returns the first usable signing key and its algorithm.
func (p *Provider) fetchClientJWK(client *storage.Client) (crypto.PublicKey, string, error) {
	if client.JWKsURI == "" {
		return nil, "", fmt.Errorf("client has no jwks_uri configured")
	}

	resp, err := http.Get(client.JWKsURI) // #nosec G107 -- URI is from trusted client registration
	if err != nil {
		return nil, "", fmt.Errorf("fetching jwks_uri: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("jwks_uri returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, "", fmt.Errorf("reading jwks_uri response: %w", err)
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, "", fmt.Errorf("parsing jwks_uri response: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return nil, "", fmt.Errorf("no keys in jwks_uri response")
	}

	// Use the first key that we can parse (ES256 or EdDSA).
	for _, keyJSON := range jwks.Keys {
		pubKey, alg, err := parseJWK(keyJSON)
		if err == nil {
			return pubKey, alg, nil
		}
	}

	return nil, "", fmt.Errorf("no usable key found in client jwks")
}
