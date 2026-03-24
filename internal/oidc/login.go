package oidc

import (
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Monet/seki/internal/config"
	"github.com/Monet/seki/web/login"
)

// loginPageData holds the template data for the login page.
type loginPageData struct {
	Issuer          string
	Error           string
	PasskeyEnabled  bool
	TOTPEnabled     bool
	PasswordEnabled bool
	SocialProviders map[string]config.SocialProvider
	OIDCParams      map[string]string
}

// oidcParamKeys are the OIDC authorization parameters to preserve through the login flow.
var oidcParamKeys = []string{
	"client_id",
	"redirect_uri",
	"response_type",
	"scope",
	"state",
	"nonce",
	"code_challenge",
	"code_challenge_method",
}

var loginTemplate = template.Must(
	template.ParseFS(login.Templates, "templates/login.html"),
)

// handleLoginPage renders the login page (GET /login).
func (p *Provider) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	data := p.buildLoginData(r.URL.Query(), "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginTemplate.Execute(w, data); err != nil {
		http.Error(w, "failed to render login page", http.StatusInternalServerError)
	}
}

// handleLoginSubmit handles password login form submission (POST /login).
func (p *Provider) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.renderLoginError(w, r, "Invalid form submission.")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		p.renderLoginError(w, r, "Email and password are required.")
		return
	}

	if !p.authnConfig.Password.Enabled {
		p.renderLoginError(w, r, "Password authentication is not enabled.")
		return
	}

	// Check brute-force lockout before attempting authentication.
	ip := loginClientIP(r)
	if p.limiter != nil && p.limiter.IsLocked(ip, email) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "urn:ietf:rfc:6585#too-many-requests",
			"title":  "Too Many Requests",
			"status": http.StatusTooManyRequests,
			"detail": "Account temporarily locked due to too many failed login attempts. Please try again later.",
		})
		return
	}

	// Look up user by email.
	user, err := p.store.GetUserByEmail(r.Context(), email)
	if err != nil {
		if p.limiter != nil {
			p.limiter.RecordLoginFailure(ip, email)
		}
		p.renderLoginError(w, r, "Invalid email or password.")
		return
	}

	// Verify password credential.
	creds, err := p.store.GetCredentialsByUserAndType(r.Context(), user.ID, "password")
	if err != nil || len(creds) == 0 {
		if p.limiter != nil {
			p.limiter.RecordLoginFailure(ip, email)
		}
		p.renderLoginError(w, r, "Invalid email or password.")
		return
	}

	if !checkPasswordHash(password, creds[0].Secret) {
		if p.limiter != nil {
			p.limiter.RecordLoginFailure(ip, email)
		}
		p.renderLoginError(w, r, "Invalid email or password.")
		return
	}

	// Login successful — reset failure counter.
	if p.limiter != nil {
		p.limiter.RecordLoginSuccess(ip, email)
	}

	p.completeLogin(w, r, user.ID)
}

// loginClientIP extracts the client IP from the request for login tracking.
func loginClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleLogout destroys the session and clears the cookie (POST /logout).
func (p *Provider) handleLogout(w http.ResponseWriter, r *http.Request) {
	if p.sessions != nil {
		if sessionID, err := p.sessions.GetSessionID(r); err == nil {
			_ = p.sessions.Delete(r.Context(), sessionID)
		}
		p.sessions.ClearCookie(w)
	}

	// Redirect to issuer root or a validated redirect.
	redirectTo := r.FormValue("redirect_uri")
	if !isSafeRedirect(redirectTo, p.issuer) {
		redirectTo = p.issuer
	}
	if redirectTo == "" {
		redirectTo = "/"
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// isSafeRedirect validates that the redirect URL belongs to the same origin
// as the issuer to prevent open redirect attacks.
func isSafeRedirect(target, issuer string) bool {
	if target == "" {
		return false
	}
	// Allow relative paths.
	if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") {
		return true
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	issuerParsed, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	// Reject javascript:, data:, vbscript: schemes.
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	// Must match the issuer's host.
	return strings.EqualFold(parsed.Host, issuerParsed.Host)
}

// completeLogin creates a session for the authenticated user and redirects
// back to /authorize with the original OIDC parameters preserved.
func (p *Provider) completeLogin(w http.ResponseWriter, r *http.Request, userID string) {
	if p.sessions == nil {
		http.Error(w, "session manager not configured", http.StatusInternalServerError)
		return
	}

	sess, err := p.sessions.Create(r.Context(), userID, "", r.RemoteAddr, r.UserAgent())
	if err != nil {
		p.renderLoginError(w, r, "Failed to create session.")
		return
	}
	p.sessions.SetCookie(w, sess)

	// Build the /authorize redirect with preserved OIDC params.
	authorizeURL := p.buildAuthorizeRedirect(r)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// buildAuthorizeRedirect reconstructs the /authorize URL from preserved OIDC form values.
func (p *Provider) buildAuthorizeRedirect(r *http.Request) string {
	q := url.Values{}
	for _, key := range oidcParamKeys {
		if v := r.FormValue(key); v != "" {
			q.Set(key, v)
		}
	}
	return "/authorize?" + q.Encode()
}

// buildLoginData constructs the template data from query parameters and config.
func (p *Provider) buildLoginData(query url.Values, errMsg string) loginPageData {
	params := make(map[string]string)
	for _, key := range oidcParamKeys {
		if v := query.Get(key); v != "" {
			params[key] = v
		}
	}

	return loginPageData{
		Issuer:          p.issuer,
		Error:           errMsg,
		PasskeyEnabled:  p.authnConfig.Passkey.Enabled,
		TOTPEnabled:     p.authnConfig.TOTP.Enabled,
		PasswordEnabled: p.authnConfig.Password.Enabled,
		SocialProviders: p.authnConfig.Social,
		OIDCParams:      params,
	}
}

// renderLoginError re-renders the login page with an error message, preserving OIDC params from the form.
func (p *Provider) renderLoginError(w http.ResponseWriter, r *http.Request, errMsg string) {
	// Reconstruct query params from the form values.
	query := url.Values{}
	for _, key := range oidcParamKeys {
		if v := r.FormValue(key); v != "" {
			query.Set(key, v)
		}
	}
	data := p.buildLoginData(query, errMsg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = loginTemplate.Execute(w, data)
}
