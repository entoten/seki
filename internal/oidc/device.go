package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/Monet/seki/internal/storage"
)

const (
	deviceCodeTTL       = 10 * time.Minute
	deviceCodeBytes     = 32
	userCodeLength      = 8
	defaultPollInterval = 5
)

// userCodeAlphabet excludes 0, O, I, L to avoid confusion.
const userCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ123456789"

var deviceTemplate = template.Must(template.New("device").Parse(devicePageHTML))

// RegisterDeviceRoutes registers the device authorization grant routes.
func (p *Provider) RegisterDeviceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /device/code", p.handleDeviceCode)
	mux.HandleFunc("GET /device", p.handleDevicePage)
	mux.HandleFunc("POST /device/verify", p.handleDeviceVerify)
}

// handleDeviceCode issues a device_code and user_code (POST /device/code).
func (p *Provider) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		tokenError(w, http.StatusBadRequest, "invalid_request", "missing client_id")
		return
	}

	// Verify client exists.
	_, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			tokenError(w, http.StatusBadRequest, "invalid_client", "unknown client")
			return
		}
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to look up client")
		return
	}

	scope := r.PostFormValue("scope")
	scopes := parseScopes(scope)

	deviceCode, err := generateDeviceCode()
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate device code")
		return
	}

	userCode, err := generateUserCode()
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate user code")
		return
	}

	now := time.Now().UTC().Truncate(time.Second)
	dc := &storage.DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     scopes,
		Status:     "pending",
		ExpiresAt:  now.Add(deviceCodeTTL),
		Interval:   defaultPollInterval,
		CreatedAt:  now,
	}

	if err := p.store.CreateDeviceCode(r.Context(), dc); err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to store device code")
		return
	}

	issuer := strings.TrimRight(p.issuer, "/")
	resp := map[string]interface{}{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          issuer + "/device",
		"verification_uri_complete": issuer + "/device?code=" + userCode,
		"expires_in":                int(deviceCodeTTL.Seconds()),
		"interval":                  defaultPollInterval,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleDevicePage renders the user code entry form (GET /device).
func (p *Provider) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	data := devicePageData{
		Issuer:  p.issuer,
		Code:    code,
		Message: "",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = deviceTemplate.Execute(w, data)
}

// handleDeviceVerify processes user code submission (POST /device/verify).
func (p *Provider) handleDeviceVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderDevicePage(w, p.issuer, "", "Invalid form submission.")
		return
	}

	userCode := strings.TrimSpace(strings.ToUpper(r.FormValue("code")))
	action := r.FormValue("action")

	if userCode == "" {
		renderDevicePage(w, p.issuer, "", "Please enter a code.")
		return
	}

	// Require an active session.
	var userID string
	if p.sessions != nil {
		sessionID, err := p.sessions.GetSessionID(r)
		if err != nil {
			// Redirect to login.
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		sess, err := p.sessions.Get(r.Context(), sessionID)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		userID = sess.UserID
	} else {
		renderDevicePage(w, p.issuer, userCode, "Session manager not configured.")
		return
	}

	dc, err := p.store.GetDeviceCodeByUserCode(r.Context(), userCode)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			renderDevicePage(w, p.issuer, "", "Invalid code. Please try again.")
			return
		}
		renderDevicePage(w, p.issuer, "", "An error occurred. Please try again.")
		return
	}

	if time.Now().UTC().After(dc.ExpiresAt) {
		renderDevicePage(w, p.issuer, "", "This code has expired. Please request a new one.")
		return
	}

	if dc.Status != "pending" {
		renderDevicePage(w, p.issuer, "", "This code has already been used.")
		return
	}

	if action == "deny" {
		_ = p.store.UpdateDeviceCodeStatus(r.Context(), dc.DeviceCode, "denied", userID)
		renderDevicePage(w, p.issuer, "", "Access denied. You can close this window.")
		return
	}

	// Approve.
	if err := p.store.UpdateDeviceCodeStatus(r.Context(), dc.DeviceCode, "approved", userID); err != nil {
		renderDevicePage(w, p.issuer, userCode, "An error occurred. Please try again.")
		return
	}

	renderDevicePage(w, p.issuer, "", "Device authorized successfully! You can close this window.")
}

// handleDeviceCodeGrant handles the token exchange for device_code grant type.
func (p *Provider) handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	deviceCode := r.PostFormValue("device_code")
	if deviceCode == "" {
		tokenError(w, http.StatusBadRequest, "invalid_request", "missing device_code parameter")
		return
	}

	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		tokenError(w, http.StatusBadRequest, "invalid_request", "missing client_id parameter")
		return
	}

	dc, err := p.store.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			tokenError(w, http.StatusBadRequest, "invalid_grant", "device code not found")
			return
		}
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to retrieve device code")
		return
	}

	if dc.ClientID != clientID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "device code was issued to a different client")
		return
	}

	if time.Now().UTC().After(dc.ExpiresAt) {
		_ = p.store.UpdateDeviceCodeStatus(ctx, dc.DeviceCode, "expired", dc.UserID)
		tokenError(w, http.StatusBadRequest, "expired_token", "device code has expired")
		return
	}

	switch dc.Status {
	case "pending":
		tokenError(w, http.StatusBadRequest, "authorization_pending", "the user has not yet completed authorization")
		return
	case "denied":
		_ = p.store.DeleteDeviceCode(ctx, dc.DeviceCode)
		tokenError(w, http.StatusBadRequest, "access_denied", "the user denied the authorization request")
		return
	case "expired":
		tokenError(w, http.StatusBadRequest, "expired_token", "device code has expired")
		return
	case "approved":
		// Continue to issue tokens.
	default:
		tokenError(w, http.StatusInternalServerError, "server_error", "unexpected device code status")
		return
	}

	// Clean up the device code.
	_ = p.store.DeleteDeviceCode(ctx, dc.DeviceCode)

	// Look up user.
	user, err := p.store.GetUser(ctx, dc.UserID)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to retrieve user")
		return
	}

	// Look up client for id_token.
	client, err := p.store.GetClient(ctx, dc.ClientID)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to retrieve client")
		return
	}

	now := time.Now().UTC()

	accessToken, err := p.generateAccessToken(user.ID, client.ID, dc.Scopes, now)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to generate access token")
		return
	}

	idToken, err := p.generateIDToken(user, client, "", "", now)
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
		Scopes:    dc.Scopes,
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

func generateDeviceCode() (string, error) {
	b := make([]byte, deviceCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateUserCode() (string, error) {
	b := make([]byte, userCodeLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := make([]byte, userCodeLength)
	for i := range code {
		code[i] = userCodeAlphabet[int(b[i])%len(userCodeAlphabet)]
	}
	return string(code), nil
}

type devicePageData struct {
	Issuer  string
	Code    string
	Message string
}

func renderDevicePage(w http.ResponseWriter, issuer, code, message string) {
	data := devicePageData{
		Issuer:  issuer,
		Code:    code,
		Message: message,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = deviceTemplate.Execute(w, data)
}

const devicePageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Authorization — {{.Issuer}}</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 1rem;
        }
        .card {
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 2rem;
            width: 100%;
            max-width: 400px;
        }
        .card h1 { font-size: 1.5rem; font-weight: 600; text-align: center; margin-bottom: 1.5rem; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; font-weight: 500; margin-bottom: 0.25rem; }
        input[type="text"] {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 1.2rem;
            text-align: center;
            letter-spacing: 0.2em;
            text-transform: uppercase;
        }
        .buttons { display: flex; gap: 0.5rem; margin-top: 1rem; }
        button {
            flex: 1;
            padding: 0.6rem;
            border: none;
            border-radius: 4px;
            font-size: 1rem;
            cursor: pointer;
        }
        .btn-approve { background: #2563eb; color: #fff; }
        .btn-approve:hover { background: #1d4ed8; }
        .btn-deny { background: #dc2626; color: #fff; }
        .btn-deny:hover { background: #b91c1c; }
        .message { text-align: center; padding: 1rem 0; color: #059669; font-weight: 500; }
        .error { color: #dc2626; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Device Authorization</h1>
        {{if .Message}}
            <p class="message">{{.Message}}</p>
        {{else}}
            <form method="POST" action="/device/verify">
                <div class="form-group">
                    <label for="code">Enter the code displayed on your device:</label>
                    <input type="text" id="code" name="code" maxlength="8" value="{{.Code}}" autocomplete="off" required>
                </div>
                <div class="buttons">
                    <button type="submit" name="action" value="approve" class="btn-approve">Approve</button>
                    <button type="submit" name="action" value="deny" class="btn-deny">Deny</button>
                </div>
            </form>
        {{end}}
    </div>
</body>
</html>`
