package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Monet/seki/internal/storage"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 30 * 24 * time.Hour // 30 days
)

// handleToken implements the OAuth 2.0 Token Endpoint (POST /token).
func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tokenError(w, http.StatusMethodNotAllowed, "invalid_request", "method must be POST")
		return
	}

	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	grantType := r.PostFormValue("grant_type")
	switch grantType {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(w, r)
	case "client_credentials":
		p.handleClientCredentialsGrant(w, r)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r)
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code, client_credentials, or refresh_token")
	}
}

// handleAuthorizationCodeGrant exchanges an authorization code for tokens.
func (p *Provider) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Authenticate client (or identify public client).
	client, err := p.authenticateClient(r)
	if err != nil {
		tokenError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	code := r.PostFormValue("code")
	if code == "" {
		tokenError(w, http.StatusBadRequest, "invalid_request", "missing code parameter")
		return
	}

	redirectURI := r.PostFormValue("redirect_uri")
	codeVerifier := r.PostFormValue("code_verifier")

	// Retrieve and validate authorization code.
	authCode, err := p.store.GetAuthCode(ctx, code)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code not found or already used")
			return
		}
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to retrieve authorization code")
		return
	}

	// Delete auth code immediately (one-time use).
	_ = p.store.DeleteAuthCode(ctx, code)

	// Validate client_id matches.
	if authCode.ClientID != client.ID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code was issued to a different client")
		return
	}

	// Validate redirect_uri matches.
	if redirectURI != "" && redirectURI != authCode.RedirectURI {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match")
		return
	}

	// Check expiry.
	if time.Now().UTC().After(authCode.ExpiresAt) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code has expired")
		return
	}

	// Verify PKCE.
	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "code_verifier is required")
			return
		}
		if !verifyPKCE(codeVerifier, authCode.CodeChallenge) {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	}

	// Look up user for id_token claims.
	user, err := p.store.GetUser(ctx, authCode.UserID)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to retrieve user")
		return
	}

	now := time.Now().UTC()

	// Generate access token.
	accessToken, err := p.generateAccessToken(user.ID, client.ID, authCode.Scopes, now)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate access token")
		return
	}

	// Generate ID token.
	idToken, err := p.generateIDToken(user, client, authCode.Nonce, now)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate id token")
		return
	}

	// Generate refresh token.
	rawRefresh, err := generateRefreshToken()
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate refresh token")
		return
	}

	family := generateFamily()
	refreshHash := hashToken(rawRefresh)
	rtID := generateTokenID()

	rt := &storage.RefreshToken{
		ID:        rtID,
		TokenHash: refreshHash,
		ClientID:  client.ID,
		UserID:    user.ID,
		Scopes:    authCode.Scopes,
		Family:    family,
		ExpiresAt: now.Add(refreshTokenTTL),
		CreatedAt: now,
	}
	if err := p.store.CreateRefreshToken(ctx, rt); err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to store refresh token")
		return
	}

	writeTokenResponse(w, accessToken, idToken, rawRefresh, int(accessTokenTTL.Seconds()))
}

// handleClientCredentialsGrant handles machine-to-machine token requests.
func (p *Provider) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	// Client must authenticate with a secret.
	client, err := p.authenticateClientWithSecret(r)
	if err != nil {
		tokenError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	// Verify client is allowed to use client_credentials grant.
	if !containsGrantType(client.GrantTypes, "client_credentials") {
		tokenError(w, http.StatusBadRequest, "unauthorized_client", "client is not authorized for client_credentials grant")
		return
	}

	now := time.Now().UTC()

	scope := r.PostFormValue("scope")
	scopes := parseScopes(scope)

	accessToken, err := p.generateAccessToken(client.ID, client.ID, scopes, now)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate access token")
		return
	}

	// client_credentials: no id_token, no refresh_token.
	writeTokenResponse(w, accessToken, "", "", int(accessTokenTTL.Seconds()))
}

// consumedTokenTime is the sentinel expiry used to mark a refresh token as consumed.
// A token with this expiry has been rotated and any reuse indicates theft.
var consumedTokenTime = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

// handleRefreshTokenGrant rotates a refresh token and issues new tokens.
func (p *Provider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rawToken := r.PostFormValue("refresh_token")
	if rawToken == "" {
		tokenError(w, http.StatusBadRequest, "invalid_request", "missing refresh_token parameter")
		return
	}

	tokenHash := hashToken(rawToken)

	// Look up the refresh token by hash.
	rt, err := p.store.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or has been revoked")
			return
		}
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to retrieve refresh token")
		return
	}

	// Theft detection: if the token was already consumed (sentinel expiry),
	// someone is reusing a rotated token. Revoke the entire family.
	if rt.ExpiresAt.Equal(consumedTokenTime) {
		_, _ = p.store.DeleteRefreshTokensByFamily(ctx, rt.Family)
		tokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected, all tokens in family revoked")
		return
	}

	// Check expiry.
	if time.Now().UTC().After(rt.ExpiresAt) {
		_ = p.store.DeleteRefreshToken(ctx, rt.ID)
		tokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token has expired")
		return
	}

	// Authenticate client if credentials are provided.
	clientID := r.PostFormValue("client_id")
	_, _, hasBasic := extractBasicAuth(r)
	if hasBasic || r.PostFormValue("client_secret") != "" {
		client, err := p.authenticateClientWithSecret(r)
		if err != nil {
			tokenError(w, http.StatusUnauthorized, "invalid_client", err.Error())
			return
		}
		clientID = client.ID
	} else if clientID == "" {
		clientID = rt.ClientID
	}

	// Verify the token belongs to this client.
	if clientID != rt.ClientID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token was issued to a different client")
		return
	}

	// Mark old refresh token as consumed (set expiry to sentinel value).
	// We keep the record so that reuse can be detected and traced to the family.
	rt.ExpiresAt = consumedTokenTime
	// Delete and re-create with consumed expiry to update the record.
	_ = p.store.DeleteRefreshToken(ctx, rt.ID)
	consumedRT := &storage.RefreshToken{
		ID:        rt.ID,
		TokenHash: rt.TokenHash,
		ClientID:  rt.ClientID,
		UserID:    rt.UserID,
		Scopes:    rt.Scopes,
		Family:    rt.Family,
		ExpiresAt: consumedTokenTime,
		CreatedAt: rt.CreatedAt,
	}
	_ = p.store.CreateRefreshToken(ctx, consumedRT)

	// Look up user.
	user, err := p.store.GetUser(ctx, rt.UserID)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to retrieve user")
		return
	}

	// Look up client for id_token.
	client, err := p.store.GetClient(ctx, rt.ClientID)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to retrieve client")
		return
	}

	now := time.Now().UTC()

	// Generate new access token.
	accessToken, err := p.generateAccessToken(user.ID, client.ID, rt.Scopes, now)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate access token")
		return
	}

	// Generate new ID token.
	idToken, err := p.generateIDToken(user, client, "", now)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate id token")
		return
	}

	// Issue new refresh token in the same family.
	newRawRefresh, err := generateRefreshToken()
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate refresh token")
		return
	}

	newRT := &storage.RefreshToken{
		ID:        generateTokenID(),
		TokenHash: hashToken(newRawRefresh),
		ClientID:  client.ID,
		UserID:    user.ID,
		Scopes:    rt.Scopes,
		Family:    rt.Family, // same family for theft detection
		ExpiresAt: now.Add(refreshTokenTTL),
		CreatedAt: now,
	}
	if err := p.store.CreateRefreshToken(ctx, newRT); err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to store refresh token")
		return
	}

	writeTokenResponse(w, accessToken, idToken, newRawRefresh, int(accessTokenTTL.Seconds()))
}

// authenticateClient identifies the client from the request. It supports
// client_secret_basic, client_secret_post, and public clients (no secret).
func (p *Provider) authenticateClient(r *http.Request) (*storage.Client, error) {
	// Try Basic auth first.
	clientID, secret, hasBasic := extractBasicAuth(r)
	if !hasBasic {
		clientID = r.PostFormValue("client_id")
		secret = r.PostFormValue("client_secret")
	}

	if clientID == "" {
		return nil, fmt.Errorf("missing client_id")
	}

	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("unknown client")
		}
		return nil, fmt.Errorf("failed to look up client")
	}

	// If client has a secret hash, verify it.
	if client.SecretHash != "" {
		if secret == "" {
			return nil, fmt.Errorf("client authentication required")
		}
		if !verifyClientSecret(secret, client.SecretHash) {
			return nil, fmt.Errorf("invalid client secret")
		}
	}

	return client, nil
}

// authenticateClientWithSecret is like authenticateClient but requires a secret.
func (p *Provider) authenticateClientWithSecret(r *http.Request) (*storage.Client, error) {
	clientID, secret, hasBasic := extractBasicAuth(r)
	if !hasBasic {
		clientID = r.PostFormValue("client_id")
		secret = r.PostFormValue("client_secret")
	}

	if clientID == "" {
		return nil, fmt.Errorf("missing client_id")
	}
	if secret == "" {
		return nil, fmt.Errorf("client secret is required")
	}

	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("unknown client")
		}
		return nil, fmt.Errorf("failed to look up client")
	}

	if client.SecretHash == "" {
		return nil, fmt.Errorf("client does not have a secret configured")
	}

	if !verifyClientSecret(secret, client.SecretHash) {
		return nil, fmt.Errorf("invalid client secret")
	}

	return client, nil
}

// extractBasicAuth extracts client credentials from the Authorization Basic header.
func extractBasicAuth(r *http.Request) (clientID, clientSecret string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// verifyClientSecret compares a plaintext secret against a bcrypt hash.
func verifyClientSecret(secret, hash string) bool {
	// Use bcrypt comparison from golang.org/x/crypto.
	// We do a simple import-free check: the hash package is already available.
	// For simplicity and to match the existing codebase pattern, we use
	// golang.org/x/crypto/bcrypt directly.
	err := bcryptCompare(hash, secret)
	return err == nil
}

// verifyPKCE verifies the PKCE code_verifier against the stored code_challenge (S256).
// Uses constant-time comparison to prevent timing side-channel attacks.
func verifyPKCE(codeVerifier, codeChallenge string) bool {
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}

// containsGrantType checks if a grant type list contains a specific grant.
func containsGrantType(grantTypes []string, target string) bool {
	for _, g := range grantTypes {
		if g == target {
			return true
		}
	}
	return false
}

// tokenError writes a JSON error response per RFC 6749 section 5.2.
func tokenError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}

// writeTokenResponse writes the successful token response.
func writeTokenResponse(w http.ResponseWriter, accessToken, idToken, refreshToken string, expiresIn int) {
	resp := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}
	if refreshToken != "" {
		resp["refresh_token"] = refreshToken
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
