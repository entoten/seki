package oidc

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/entoten/seki/internal/storage"
	"github.com/entoten/seki/web/login"
)

// sessionMFAMeta is the structure stored in session.Metadata for MFA state.
type sessionMFAMeta struct {
	MFAVerified   bool   `json:"mfa_verified"`
	MFAMethod     string `json:"mfa_method,omitempty"`
	MFAVerifiedAt string `json:"mfa_verified_at,omitempty"`
}

// sessionHasMFA returns true if the session metadata indicates MFA was completed.
func sessionHasMFA(sess *storage.Session) bool {
	if len(sess.Metadata) == 0 {
		return false
	}
	var meta sessionMFAMeta
	if err := json.Unmarshal(sess.Metadata, &meta); err != nil {
		return false
	}
	return meta.MFAVerified
}

// containsACR checks whether a space-delimited acr_values string contains a specific ACR.
func containsACR(acrValues, target string) bool {
	for _, v := range strings.Fields(acrValues) {
		if v == target {
			return true
		}
	}
	return false
}

// redirectToMFA sends the user to the MFA challenge page, preserving OIDC query params.
func (p *Provider) redirectToMFA(w http.ResponseWriter, r *http.Request) {
	mfaURL := "/mfa?" + r.URL.RawQuery
	http.Redirect(w, r, mfaURL, http.StatusFound)
}

// mfaPageData holds the template data for the MFA challenge page.
type mfaPageData struct {
	Issuer         string
	Error          string
	TOTPEnabled    bool
	PasskeyEnabled bool
	OIDCParams     map[string]string
}

var mfaTemplate = template.Must(
	template.ParseFS(login.Templates, "templates/mfa.html"),
)

// handleMFAPage renders the MFA challenge page (GET /mfa).
func (p *Provider) handleMFAPage(w http.ResponseWriter, r *http.Request) {
	if p.sessions == nil {
		http.Error(w, "session manager not configured", http.StatusInternalServerError)
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

	data := p.buildMFAData(r.URL.Query(), "", sess.UserID)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := mfaTemplate.Execute(w, data); err != nil {
		http.Error(w, "failed to render MFA page", http.StatusInternalServerError)
	}
}

// handleMFASubmit verifies the MFA challenge and updates the session (POST /mfa).
func (p *Provider) handleMFASubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.renderMFAError(w, r, "Invalid form submission.", "")
		return
	}

	if p.sessions == nil {
		http.Error(w, "session manager not configured", http.StatusInternalServerError)
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

	mfaMethod := r.FormValue("mfa_method")
	totpCode := r.FormValue("totp_code")

	switch mfaMethod {
	case "totp":
		if totpCode == "" {
			p.renderMFAError(w, r, "TOTP code is required.", sess.UserID)
			return
		}
		if !p.verifyTOTP(r, sess.UserID, totpCode) {
			p.renderMFAError(w, r, "Invalid TOTP code.", sess.UserID)
			return
		}
	case "passkey":
		// Passkey step-up verification requires WebAuthn assertion validation.
		// This is a placeholder; a full implementation would verify the
		// authenticator assertion response here.
		p.renderMFAError(w, r, "Passkey step-up verification is not yet implemented.", sess.UserID)
		return
	default:
		p.renderMFAError(w, r, "Unsupported MFA method.", sess.UserID)
		return
	}

	// MFA verified — update session metadata.
	meta := sessionMFAMeta{
		MFAVerified:   true,
		MFAMethod:     mfaMethod,
		MFAVerifiedAt: time.Now().UTC().Format(time.RFC3339),
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		p.renderMFAError(w, r, "Failed to update session.", sess.UserID)
		return
	}

	if err := p.sessions.UpdateMetadata(r.Context(), sessionID, json.RawMessage(metaJSON)); err != nil {
		p.renderMFAError(w, r, "Failed to update session.", sess.UserID)
		return
	}

	// Redirect back to /authorize with the original OIDC params.
	authorizeURL := p.buildAuthorizeRedirectFromForm(r)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// verifyTOTP checks a TOTP code against the user's stored TOTP credential.
func (p *Provider) verifyTOTP(r *http.Request, userID, code string) bool {
	creds, err := p.store.GetCredentialsByUserAndType(r.Context(), userID, "totp")
	if err != nil || len(creds) == 0 {
		return false
	}
	return validateTOTPCode(creds[0].Secret, code)
}

// validateTOTPCode validates a TOTP code against the given secret.
func validateTOTPCode(secret []byte, code string) bool {
	return totp.Validate(code, string(secret))
}

// buildMFAData constructs the template data for the MFA page.
func (p *Provider) buildMFAData(query url.Values, errMsg, userID string) mfaPageData {
	params := make(map[string]string)
	for _, key := range oidcParamKeys {
		if v := query.Get(key); v != "" {
			params[key] = v
		}
	}

	// Determine which MFA methods are available for this user.
	totpAvailable := false
	passkeyAvailable := false

	ctx := context.Background()
	if p.authnConfig.TOTP.Enabled && userID != "" {
		creds, err := p.store.GetCredentialsByUserAndType(ctx, userID, "totp")
		if err == nil && len(creds) > 0 {
			totpAvailable = true
		}
	}
	if p.authnConfig.Passkey.Enabled && userID != "" {
		creds, err := p.store.GetCredentialsByUserAndType(ctx, userID, "passkey")
		if err == nil && len(creds) > 0 {
			passkeyAvailable = true
		}
	}

	return mfaPageData{
		Issuer:         p.issuer,
		Error:          errMsg,
		TOTPEnabled:    totpAvailable,
		PasskeyEnabled: passkeyAvailable,
		OIDCParams:     params,
	}
}

// renderMFAError re-renders the MFA page with an error message.
func (p *Provider) renderMFAError(w http.ResponseWriter, r *http.Request, errMsg, userID string) {
	query := url.Values{}
	for _, key := range oidcParamKeys {
		if v := r.FormValue(key); v != "" {
			query.Set(key, v)
		}
	}
	data := p.buildMFAData(query, errMsg, userID)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = mfaTemplate.Execute(w, data)
}

// buildAuthorizeRedirectFromForm reconstructs the /authorize URL from preserved OIDC form values.
func (p *Provider) buildAuthorizeRedirectFromForm(r *http.Request) string {
	q := url.Values{}
	for _, key := range oidcParamKeys {
		if v := r.FormValue(key); v != "" {
			q.Set(key, v)
		}
	}
	return "/authorize?" + q.Encode()
}
