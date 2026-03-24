package client

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// OAuthClient represents an OAuth2/OIDC client registered with seki.
type OAuthClient struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scopes       []string `json:"scopes"`
	PKCERequired bool     `json:"pkce_required"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// CreateClientInput is the input for creating an OAuth client.
type CreateClientInput struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	GrantTypes   []string `json:"grant_types,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	PKCERequired *bool    `json:"pkce_required,omitempty"`
}

// clientListResponse matches the server's JSON envelope for client lists.
type clientListResponse struct {
	Data []OAuthClient `json:"data"`
}

// CreateClient creates a new OAuth client.
func (c *Client) CreateClient(ctx context.Context, input CreateClientInput) (*OAuthClient, error) {
	var oc OAuthClient
	err := c.do(ctx, http.MethodPost, "/api/v1/clients", nil, input, &oc)
	if err != nil {
		return nil, err
	}
	return &oc, nil
}

// GetClient retrieves an OAuth client by ID.
func (c *Client) GetClient(ctx context.Context, id string) (*OAuthClient, error) {
	var oc OAuthClient
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/clients/%s", id), nil, nil, &oc)
	if err != nil {
		return nil, err
	}
	return &oc, nil
}

// ListClients returns all registered OAuth clients.
func (c *Client) ListClients(ctx context.Context) ([]OAuthClient, error) {
	var resp clientListResponse
	err := c.do(ctx, http.MethodGet, "/api/v1/clients", nil, nil, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// DeleteClient deletes an OAuth client by ID.
func (c *Client) DeleteClient(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/clients/%s", id), nil, nil, nil)
}
