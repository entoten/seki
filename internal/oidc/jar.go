package oidc

import (
	"fmt"
	"net/http"

	"github.com/entoten/seki/internal/storage"
	"github.com/golang-jwt/jwt/v5"
)

// resolveJAR checks for a "request" parameter (RFC 9101 JAR) in the authorize
// request. If present, it decodes and verifies the JWT, then returns the
// extracted parameters. The client must have a jwks_uri configured.
//
// Returns:
//   - (params, true) if a request JWT was present and valid
//   - (nil, true) if a request JWT was present but invalid (error already written)
//   - (nil, false) if no request parameter was present
func (p *Provider) resolveJAR(w http.ResponseWriter, r *http.Request, client *storage.Client) (map[string]string, bool) {
	q := r.URL.Query()
	requestJWT := q.Get("request")
	if requestJWT == "" {
		return nil, false
	}

	// Fetch the client's public key for signature verification.
	pubKey, alg, err := p.fetchClientJWK(client)
	if err != nil {
		renderError(w, http.StatusBadRequest, "invalid_request_object", "unable to verify request JWT: "+err.Error())
		return nil, true
	}

	// Parse and verify the JWT signature.
	token, err := jwt.Parse(requestJWT, func(t *jwt.Token) (interface{}, error) {
		return pubKey, nil
	}, jwt.WithValidMethods([]string{alg}))
	if err != nil {
		renderError(w, http.StatusBadRequest, "invalid_request_object", "request JWT signature verification failed: "+err.Error())
		return nil, true
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		renderError(w, http.StatusBadRequest, "invalid_request_object", "invalid claims in request JWT")
		return nil, true
	}

	// Verify iss == client_id (RFC 9101 Section 6.1).
	iss, _ := claims["iss"].(string)
	if iss != client.ID {
		renderError(w, http.StatusBadRequest, "invalid_request_object", fmt.Sprintf("request JWT iss (%q) does not match client_id (%q)", iss, client.ID))
		return nil, true
	}

	// Verify aud contains the issuer (RFC 9101 Section 6.2).
	if !audienceContains(claims, p.issuer) {
		renderError(w, http.StatusBadRequest, "invalid_request_object", "request JWT aud does not contain the authorization server issuer")
		return nil, true
	}

	// Extract claims as authorization parameters.
	params := make(map[string]string)
	for _, key := range []string{
		"redirect_uri", "response_type", "scope", "state", "nonce",
		"code_challenge", "code_challenge_method", "acr_values", "resource",
	} {
		if v, ok := claims[key].(string); ok && v != "" {
			params[key] = v
		}
	}

	// client_id from JWT must match query param if present.
	if jwtClientID, ok := claims["client_id"].(string); ok && jwtClientID != "" {
		if jwtClientID != client.ID {
			renderError(w, http.StatusBadRequest, "invalid_request_object", "client_id in request JWT does not match query parameter")
			return nil, true
		}
	}

	return params, true
}
