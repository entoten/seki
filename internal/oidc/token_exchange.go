package oidc

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const (
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// handleTokenExchangeGrant implements RFC 8693 Token Exchange.
func (p *Provider) handleTokenExchangeGrant(w http.ResponseWriter, r *http.Request) {
	// Authenticate the requesting client.
	client, err := p.authenticateClientAll(r)
	if err != nil {
		tokenError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	// Verify client is authorized for token-exchange grant.
	if !containsGrantType(client.GrantTypes, "urn:ietf:params:oauth:grant-type:token-exchange") {
		tokenError(w, http.StatusBadRequest, "unauthorized_client", "client is not authorized for token-exchange grant")
		return
	}

	subjectToken := r.PostFormValue("subject_token")
	if subjectToken == "" {
		tokenError(w, http.StatusBadRequest, "invalid_request", "missing subject_token parameter")
		return
	}

	subjectTokenType := r.PostFormValue("subject_token_type")
	if subjectTokenType == "" {
		subjectTokenType = tokenTypeAccessToken
	}
	if subjectTokenType != tokenTypeAccessToken {
		tokenError(w, http.StatusBadRequest, "invalid_request", "unsupported subject_token_type")
		return
	}

	// Validate the subject_token by verifying it as a JWT access token.
	subjectClaims, err := p.signer.Verify(subjectToken)
	if err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "invalid subject_token")
		return
	}

	// Extract subject info.
	sub, _ := subjectClaims["sub"].(string)
	if sub == "" {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "subject_token has no sub claim")
		return
	}

	// Determine scopes for the exchanged token.
	requestedScope := r.PostFormValue("scope")
	var scopes []string
	if requestedScope != "" {
		scopes = strings.Fields(requestedScope)
	} else {
		// Inherit from subject token.
		if scopeStr, ok := subjectClaims["scope"].(string); ok {
			scopes = strings.Fields(scopeStr)
		}
	}

	// Determine audience.
	audience := r.PostFormValue("audience")
	if audience == "" {
		audience = client.ID
	}

	now := time.Now().UTC()

	// Build access token claims.
	accessClaims := map[string]interface{}{
		"sub":   sub,
		"aud":   audience,
		"scope": strings.Join(scopes, " "),
		"iat":   now.Unix(),
		"exp":   now.Add(accessTokenTTL).Unix(),
		"iss":   p.issuer,
		"typ":   "access_token",
	}

	// If actor_token is provided, add act claim.
	actorToken := r.PostFormValue("actor_token")
	if actorToken != "" {
		actorClaims, err := p.signer.Verify(actorToken)
		if err != nil {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "invalid actor_token")
			return
		}
		actorSub, _ := actorClaims["sub"].(string)
		if actorSub != "" {
			accessClaims["act"] = map[string]interface{}{
				"sub": actorSub,
			}
		}
	}

	accessToken, err := p.signer.Sign(accessClaims)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate access token")
		return
	}

	// Write token exchange response per RFC 8693.
	resp := map[string]interface{}{
		"access_token":      accessToken,
		"token_type":        "Bearer",
		"expires_in":        int(accessTokenTTL.Seconds()),
		"issued_token_type": tokenTypeAccessToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
