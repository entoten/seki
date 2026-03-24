package client

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Role represents a named role with permissions within an organization.
type Role struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Name        string    `json:"name"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateRoleInput is the input for creating a role.
type CreateRoleInput struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions,omitempty"`
}

// UpdateRoleInput is the input for updating a role.
type UpdateRoleInput struct {
	Permissions []string `json:"permissions"`
}

// roleListResponse matches the server's JSON envelope for role lists.
type roleListResponse struct {
	Data []Role `json:"data"`
}

// CreateRole creates a new role in an organization.
func (c *Client) CreateRole(ctx context.Context, slug string, input CreateRoleInput) (*Role, error) {
	var role Role
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/orgs/%s/roles", slug), nil, input, &role)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// ListRoles returns all roles in an organization.
func (c *Client) ListRoles(ctx context.Context, slug string) ([]Role, error) {
	var resp roleListResponse
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/orgs/%s/roles", slug), nil, nil, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// UpdateRole updates a role's permissions.
func (c *Client) UpdateRole(ctx context.Context, slug, name string, input UpdateRoleInput) (*Role, error) {
	var role Role
	err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/api/v1/orgs/%s/roles/%s", slug, name), nil, input, &role)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// DeleteRole deletes a role by name from an organization.
func (c *Client) DeleteRole(ctx context.Context, slug, name string) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/orgs/%s/roles/%s", slug, name), nil, nil, nil)
}
