package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// handleIntrospect implements the OAuth 2.0 Token Introspection endpoint (RFC 7662).
// POST /introspect
func (p *Provider) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tokenError(w, http.StatusMethodNotAllowed, "invalid_request", "method must be POST")
		return
	}

	// Authenticate the caller via client credentials.
	_, err := p.authenticateClientWithSecret(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Basic")
		tokenError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	token := r.PostFormValue("token")
	if token == "" {
		tokenError(w, http.StatusBadRequest, "invalid_request", "missing token parameter")
		return
	}

	ctx := r.Context()
	tokenTypeHint := r.PostFormValue("token_type_hint")

	// Try to introspect based on hint, falling back to other types.
	switch tokenTypeHint {
	case "refresh_token":
		if p.introspectRefreshToken(ctx, w, token) {
			return
		}
		if p.introspectPAT(ctx, w, token) {
			return
		}
		if p.introspectAccessToken(w, token) {
			return
		}
	case "access_token", "":
		if p.introspectAccessToken(w, token) {
			return
		}
		if p.introspectRefreshToken(ctx, w, token) {
			return
		}
		if p.introspectPAT(ctx, w, token) {
			return
		}
	default:
		// Unknown hint; try all types.
		if p.introspectAccessToken(w, token) {
			return
		}
		if p.introspectRefreshToken(ctx, w, token) {
			return
		}
		if p.introspectPAT(ctx, w, token) {
			return
		}
	}

	// Token is not active (invalid, expired, or unknown).
	writeIntrospectResponse(w, map[string]interface{}{"active": false})
}

// introspectAccessToken attempts to verify the token as a JWT access token.
// Returns true if a response was written.
func (p *Provider) introspectAccessToken(w http.ResponseWriter, token string) bool {
	claims, err := p.signer.Verify(token)
	if err != nil {
		return false
	}

	// Check that this is an access token.
	if typ, ok := claims["typ"].(string); ok && typ != "access_token" {
		return false
	}

	// Determine token type based on cnf claim.
	tokenType := "Bearer"
	if cnf, ok := claims["cnf"]; ok {
		tokenType = "DPoP"
		resp := map[string]interface{}{
			"active":     true,
			"token_type": tokenType,
			"cnf":        cnf,
		}
		if sub, ok := claims["sub"]; ok {
			resp["sub"] = sub
		}
		if scope, ok := claims["scope"]; ok {
			resp["scope"] = scope
		}
		if aud, ok := claims["aud"]; ok {
			resp["client_id"] = aud
		}
		if exp, ok := claims["exp"]; ok {
			resp["exp"] = exp
		}
		if iat, ok := claims["iat"]; ok {
			resp["iat"] = iat
		}
		if iss, ok := claims["iss"]; ok {
			resp["iss"] = iss
		}
		writeIntrospectResponse(w, resp)
		return true
	}

	// Build introspection response from JWT claims.
	resp := map[string]interface{}{
		"active":     true,
		"token_type": tokenType,
	}

	if sub, ok := claims["sub"]; ok {
		resp["sub"] = sub
	}
	if scope, ok := claims["scope"]; ok {
		resp["scope"] = scope
	}
	if aud, ok := claims["aud"]; ok {
		resp["client_id"] = aud
	}
	if exp, ok := claims["exp"]; ok {
		resp["exp"] = exp
	}
	if iat, ok := claims["iat"]; ok {
		resp["iat"] = iat
	}
	if iss, ok := claims["iss"]; ok {
		resp["iss"] = iss
	}

	writeIntrospectResponse(w, resp)
	return true
}

// introspectRefreshToken attempts to look up the token as a refresh token.
// Returns true if a response was written.
func (p *Provider) introspectRefreshToken(ctx context.Context, w http.ResponseWriter, token string) bool {
	hash := hashToken(token)
	rt, err := p.store.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		return false
	}

	now := time.Now().UTC()

	// Check if consumed (sentinel) or expired.
	if rt.ExpiresAt.Equal(consumedTokenTime) || now.After(rt.ExpiresAt) {
		writeIntrospectResponse(w, map[string]interface{}{"active": false})
		return true
	}

	resp := map[string]interface{}{
		"active":     true,
		"token_type": "Bearer",
		"client_id":  rt.ClientID,
		"sub":        rt.UserID,
		"scope":      strings.Join(rt.Scopes, " "),
		"exp":        rt.ExpiresAt.Unix(),
		"iat":        rt.CreatedAt.Unix(),
	}

	writeIntrospectResponse(w, resp)
	return true
}

// introspectPAT attempts to look up the token as a personal access token.
// Returns true if a response was written.
func (p *Provider) introspectPAT(ctx context.Context, w http.ResponseWriter, token string) bool {
	hash := hashToken(token)
	pat, err := p.store.GetPATByHash(ctx, hash)
	if err != nil {
		return false
	}

	now := time.Now().UTC()

	if now.After(pat.ExpiresAt) {
		writeIntrospectResponse(w, map[string]interface{}{"active": false})
		return true
	}

	resp := map[string]interface{}{
		"active":     true,
		"token_type": "Bearer",
		"sub":        pat.UserID,
		"scope":      strings.Join(pat.Scopes, " "),
		"exp":        pat.ExpiresAt.Unix(),
		"iat":        pat.CreatedAt.Unix(),
	}

	writeIntrospectResponse(w, resp)
	return true
}

// writeIntrospectResponse writes the JSON introspection response.
func writeIntrospectResponse(w http.ResponseWriter, resp map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
