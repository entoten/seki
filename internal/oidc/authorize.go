package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/internal/telemetry"
	"github.com/entoten/seki/internal/validate"
)

// authCodeTTL is the lifetime of an authorization code.
const authCodeTTL = 10 * time.Minute

// handleAuthorize implements the OAuth 2.0 Authorization Endpoint.
func (p *Provider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "oidc.authorize")
	defer span.End()
	r = r.WithContext(ctx)

	// --- Check for Pushed Authorization Request (PAR) ---
	if client, parReq, handled := p.resolveAuthorizeParamsFromPAR(w, r); handled {
		if parReq == nil {
			// Error was already written by resolveAuthorizeParamsFromPAR.
			return
		}
		// Use PAR-stored parameters.
		p.completeAuthorize(w, r, client, parReq.RedirectURI, parReq.Scope, parReq.State,
			parReq.Nonce, parReq.CodeChallenge, parReq.CodeChallengeMethod, parReq.ACRValues)
		return
	}

	q := r.URL.Query()

	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	nonce := q.Get("nonce")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	// --- Validate client_id ---
	if clientID == "" {
		renderError(w, http.StatusBadRequest, "invalid_request", "missing client_id parameter")
		return
	}

	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			renderError(w, http.StatusBadRequest, "invalid_request", "unknown client_id")
			return
		}
		renderError(w, http.StatusInternalServerError, "server_error", "failed to look up client")
		return
	}

	// --- Validate redirect_uri (MUST happen before we redirect errors) ---
	if err := validate.RedirectURI(redirectURI); err != nil {
		renderError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if !isValidRedirectURI(client, redirectURI) {
		// Per OAuth 2.0 spec: NEVER redirect to an unvalidated redirect_uri.
		renderError(w, http.StatusBadRequest, "invalid_request", "redirect_uri does not match any registered URI for this client")
		return
	}

	parsed, err := url.Parse(redirectURI)
	if err != nil {
		renderError(w, http.StatusBadRequest, "invalid_request", "malformed redirect_uri")
		return
	}

	// From this point on, errors are redirected back to the redirect_uri.

	// --- Validate response_type ---
	if responseType == "" {
		redirectWithError(w, r, parsed, state, "invalid_request", "missing response_type parameter")
		return
	}
	if responseType != "code" {
		redirectWithError(w, r, parsed, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}

	// --- Validate scope ---
	scopes := parseScopes(scope)
	if !containsScope(scopes, "openid") {
		redirectWithError(w, r, parsed, state, "invalid_scope", "scope must include openid")
		return
	}

	// --- Validate PKCE ---
	if client.PKCERequired {
		if codeChallenge == "" {
			redirectWithError(w, r, parsed, state, "invalid_request", "code_challenge is required")
			return
		}
		if codeChallengeMethod == "" {
			redirectWithError(w, r, parsed, state, "invalid_request", "code_challenge_method is required")
			return
		}
	}
	if codeChallengeMethod != "" && codeChallengeMethod != "S256" {
		redirectWithError(w, r, parsed, state, "invalid_request", "only code_challenge_method=S256 is supported")
		return
	}

	// --- Check for active session ---
	if p.sessions == nil {
		redirectWithError(w, r, parsed, state, "login_required", "no session manager configured")
		return
	}

	sessionID, err := p.sessions.GetSessionID(r)
	if err != nil {
		p.redirectToLogin(w, r)
		return
	}

	sess, err := p.sessions.Get(r.Context(), sessionID)
	if err != nil {
		p.redirectToLogin(w, r)
		return
	}

	// --- Check acr_values for step-up MFA ---
	acrValues := q.Get("acr_values")
	mfaRequired := containsACR(acrValues, ACRMFA)
	mfaVerified := sessionHasMFA(sess)

	if mfaRequired && !mfaVerified {
		p.redirectToMFA(w, r)
		return
	}

	// --- Generate authorization code ---
	code, err := generateAuthCode()
	if err != nil {
		redirectWithError(w, r, parsed, state, "server_error", "failed to generate authorization code")
		return
	}

	// Determine achieved ACR level.
	acr := ACRBasic
	if mfaVerified {
		acr = ACRMFA
	}

	now := time.Now().UTC()
	authCode := &storage.AuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              sess.UserID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
		State:               state,
		ACR:                 acr,
		ExpiresAt:           now.Add(authCodeTTL),
		CreatedAt:           now,
	}

	if err := p.store.CreateAuthCode(r.Context(), authCode); err != nil {
		redirectWithError(w, r, parsed, state, "server_error", "failed to store authorization code")
		return
	}

	// --- Redirect with code (RFC 9207: include iss parameter) ---
	rq := parsed.Query()
	rq.Set("code", code)
	if state != "" {
		rq.Set("state", state)
	}
	rq.Set("iss", p.issuer)
	parsed.RawQuery = rq.Encode()

	http.Redirect(w, r, parsed.String(), http.StatusFound)
}

// completeAuthorize handles the authorize flow using pre-validated parameters (from PAR).
func (p *Provider) completeAuthorize(w http.ResponseWriter, r *http.Request, client *storage.Client, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, acrValues string) {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		renderError(w, http.StatusBadRequest, "invalid_request", "malformed redirect_uri")
		return
	}

	scopes := parseScopes(scope)

	// --- Check for active session ---
	if p.sessions == nil {
		redirectWithError(w, r, parsed, state, "login_required", "no session manager configured")
		return
	}

	sessionID, err := p.sessions.GetSessionID(r)
	if err != nil {
		p.redirectToLogin(w, r)
		return
	}

	sess, err := p.sessions.Get(r.Context(), sessionID)
	if err != nil {
		p.redirectToLogin(w, r)
		return
	}

	// --- Check acr_values for step-up MFA ---
	mfaRequired := containsACR(acrValues, ACRMFA)
	mfaVerified := sessionHasMFA(sess)

	if mfaRequired && !mfaVerified {
		p.redirectToMFA(w, r)
		return
	}

	// --- Generate authorization code ---
	code, err := generateAuthCode()
	if err != nil {
		redirectWithError(w, r, parsed, state, "server_error", "failed to generate authorization code")
		return
	}

	acr := ACRBasic
	if mfaVerified {
		acr = ACRMFA
	}

	now := time.Now().UTC()
	authCode := &storage.AuthCode{
		Code:                code,
		ClientID:            client.ID,
		UserID:              sess.UserID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
		State:               state,
		ACR:                 acr,
		ExpiresAt:           now.Add(authCodeTTL),
		CreatedAt:           now,
	}

	if err := p.store.CreateAuthCode(r.Context(), authCode); err != nil {
		redirectWithError(w, r, parsed, state, "server_error", "failed to store authorization code")
		return
	}

	// --- Redirect with code (RFC 9207: include iss parameter) ---
	rq := parsed.Query()
	rq.Set("code", code)
	if state != "" {
		rq.Set("state", state)
	}
	rq.Set("iss", p.issuer)
	parsed.RawQuery = rq.Encode()

	http.Redirect(w, r, parsed.String(), http.StatusFound)
}

// isValidRedirectURI performs exact-match comparison against the client's registered URIs.
func isValidRedirectURI(client *storage.Client, uri string) bool {
	for _, registered := range client.RedirectURIs {
		if registered == uri {
			return true
		}
	}
	return false
}

// parseScopes splits a space-delimited scope string.
func parseScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

// containsScope checks if a scope list contains a specific scope.
func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// generateAuthCode generates a cryptographically random authorization code.
func generateAuthCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate auth code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// redirectWithError redirects back to the client's redirect_uri with an error.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI *url.URL, state, errorCode, description string) {
	q := redirectURI.Query()
	q.Set("error", errorCode)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	redirectURI.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

// redirectToLogin sends the user to the login page, preserving OIDC query params.
func (p *Provider) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	loginURL := "/login?" + r.URL.RawQuery
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// renderError displays an error page for cases where we cannot safely redirect.
func renderError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "error: %s\n%s\n", errorCode, description) // #nosec G705 -- false positive: Content-Type is text/plain, no XSS risk
}
