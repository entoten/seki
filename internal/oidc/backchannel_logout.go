package oidc

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

// triggerBackChannelLogout sends logout tokens to all clients with a
// backchannel_logout_uri that the user has sessions with.
// It runs asynchronously so as not to block the logout response.
func (p *Provider) triggerBackChannelLogout(ctx context.Context, userID, sessionID string) {
	go p.sendBackChannelLogouts(userID, sessionID)
}

// sendBackChannelLogouts iterates over all registered clients and sends
// logout tokens to those with a backchannel_logout_uri configured.
func (p *Provider) sendBackChannelLogouts(userID, sessionID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clients, err := p.store.ListClients(ctx)
	if err != nil {
		return
	}

	now := time.Now().UTC()
	for _, client := range clients {
		if client.BackChannelLogoutURI == "" {
			continue
		}
		logoutToken, err := p.generateLogoutToken(userID, client.ID, sessionID, client.BackChannelLogoutSessionReq, now)
		if err != nil {
			continue
		}
		p.postLogoutToken(client.BackChannelLogoutURI, logoutToken)
	}
}

// generateLogoutToken creates a signed Logout Token JWT per OIDC Back-Channel Logout spec.
func (p *Provider) generateLogoutToken(userID, clientID, sessionID string, includeSID bool, now time.Time) (string, error) {
	claims := map[string]interface{}{
		"iss": p.issuer,
		"sub": userID,
		"aud": clientID,
		"iat": now.Unix(),
		"jti": uuid.New().String(),
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
	}
	if includeSID && sessionID != "" {
		claims["sid"] = sessionID
	}
	return p.signer.Sign(claims)
}

// postLogoutToken POSTs the logout_token to the client's back-channel logout URI.
func (p *Provider) postLogoutToken(logoutURI, logoutToken string) {
	data := url.Values{"logout_token": {logoutToken}}
	resp, err := http.PostForm(logoutURI, data) // #nosec G107 -- URI from trusted client registration
	if err != nil {
		return
	}
	resp.Body.Close()
}
