package oidc

import (
	"context"
	"net/http"
)

// handleRevoke implements the OAuth 2.0 Token Revocation endpoint (RFC 7009).
// POST /revoke
// Per the spec, the endpoint always returns 200 for valid requests, even if
// the token is invalid or already revoked, to prevent token probing.
func (p *Provider) handleRevoke(w http.ResponseWriter, r *http.Request) {
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
		// Per RFC 7009, return 200 even for empty tokens.
		w.WriteHeader(http.StatusOK)
		return
	}

	ctx := r.Context()
	tokenTypeHint := r.PostFormValue("token_type_hint")

	// Try to revoke based on hint, falling back to other types.
	switch tokenTypeHint {
	case "refresh_token":
		if p.revokeRefreshToken(ctx, token) {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Try PAT as fallback.
		p.revokePAT(ctx, token)
	case "access_token":
		// JWTs cannot be revoked; return 200 per spec.
		// Try refresh token and PAT as fallback in case the hint is wrong.
		if !p.revokeRefreshToken(ctx, token) {
			p.revokePAT(ctx, token)
		}
	default:
		// No hint or unknown hint; try all types.
		if !p.revokeRefreshToken(ctx, token) {
			p.revokePAT(ctx, token)
		}
	}

	// Always return 200 per RFC 7009.
	w.WriteHeader(http.StatusOK)
}

// revokeRefreshToken attempts to find and delete a refresh token by hash.
// Returns true if a token was found and deleted.
func (p *Provider) revokeRefreshToken(ctx context.Context, token string) bool {
	hash := hashToken(token)
	rt, err := p.store.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		return false
	}
	_ = p.store.DeleteRefreshToken(ctx, rt.ID)
	return true
}

// revokePAT attempts to find and delete a personal access token by hash.
// Returns true if a token was found and deleted.
func (p *Provider) revokePAT(ctx context.Context, token string) bool {
	hash := hashToken(token)
	pat, err := p.store.GetPATByHash(ctx, hash)
	if err != nil {
		return false
	}
	_ = p.store.DeletePAT(ctx, pat.ID)
	return true
}
