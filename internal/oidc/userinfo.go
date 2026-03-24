package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Monet/seki/internal/storage"
)

// handleUserInfo serves the OIDC UserInfo endpoint (GET /userinfo).
// It validates the Bearer access token, looks up the user, and returns
// standard OIDC claims based on the scopes present in the token.
func (p *Provider) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	claims, err := p.validateAccessToken(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_token",
			"error_description": "token validation failed",
		})
		return
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_token",
			"error_description": "missing sub claim",
		})
		return
	}

	user, err := p.store.GetUser(r.Context(), sub)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "not_found",
				"error_description": "user not found",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": "failed to retrieve user",
		})
		return
	}

	// Parse scopes from the token.
	var scopes []string
	if scopeStr, ok := claims["scope"].(string); ok {
		scopes = strings.Fields(scopeStr)
	}

	// Build the response based on scopes.
	resp := map[string]interface{}{
		"sub": user.ID,
	}

	if containsScope(scopes, "profile") {
		if user.DisplayName != "" {
			resp["name"] = user.DisplayName
		}
		resp["preferred_username"] = user.ID
	}

	if containsScope(scopes, "email") {
		if user.Email != "" {
			resp["email"] = user.Email
			resp["email_verified"] = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// validateAccessToken extracts and validates a Bearer token from the
// Authorization header. It returns the JWT claims on success.
func (p *Provider) validateAccessToken(r *http.Request) (map[string]interface{}, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, fmt.Errorf("authorization header must use Bearer scheme")
	}

	tokenString := strings.TrimPrefix(auth, "Bearer ")
	if tokenString == "" {
		return nil, fmt.Errorf("empty bearer token")
	}

	claims, err := p.signer.Verify(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Verify token type if present.
	if typ, ok := claims["typ"].(string); ok && typ != "access_token" {
		return nil, fmt.Errorf("token is not an access token")
	}

	return claims, nil
}
