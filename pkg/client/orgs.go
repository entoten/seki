package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Organization represents a seki organization/tenant.
type Organization struct {
	ID        string          `json:"id"`
	Slug      string          `json:"slug"`
	Name      string          `json:"name"`
	Domains   []string        `json:"domains"`
	Metadata  json.RawMessage `json:"metadata"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// OrgMember represents a user's membership in an organization.
type OrgMember struct {
	OrgID    string    `json:"org_id"`
	UserID   string    `json:"user_id"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

// CreateOrgInput is the input for creating an organization.
type CreateOrgInput struct {
	ID       string          `json:"id,omitempty"`
	Slug     string          `json:"slug"`
	Name     string          `json:"name"`
	Domains  []string        `json:"domains,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// UpdateOrgInput is the input for updating an organization.
type UpdateOrgInput struct {
	Name     *string          `json:"name,omitempty"`
	Slug     *string          `json:"slug,omitempty"`
	Domains  []string         `json:"domains,omitempty"`
	Metadata *json.RawMessage `json:"metadata,omitempty"`
}

// AddMemberInput is the input for adding a member to an organization.
type AddMemberInput struct {
	UserID string `json:"user_id"`
	Role   string `json:"role,omitempty"`
}

// UpdateMemberRoleInput is the input for changing a member's role.
type UpdateMemberRoleInput struct {
	Role string `json:"role"`
}

// CreateOrg creates a new organization.
func (c *Client) CreateOrg(ctx context.Context, input CreateOrgInput) (*Organization, error) {
	var org Organization
	err := c.do(ctx, http.MethodPost, "/api/v1/orgs", nil, input, &org)
	if err != nil {
		return nil, err
	}
	return &org, nil
}

// GetOrg retrieves an organization by slug.
func (c *Client) GetOrg(ctx context.Context, slug string) (*Organization, error) {
	var org Organization
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/orgs/%s", slug), nil, nil, &org)
	if err != nil {
		return nil, err
	}
	return &org, nil
}

// ListOrgs returns a paginated list of organizations.
func (c *Client) ListOrgs(ctx context.Context, opts ListOptions) (*ListResult[Organization], error) {
	var resp ListResult[Organization]
	err := c.do(ctx, http.MethodGet, "/api/v1/orgs", opts.queryParams(), nil, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateOrg updates an existing organization.
func (c *Client) UpdateOrg(ctx context.Context, slug string, input UpdateOrgInput) (*Organization, error) {
	var org Organization
	err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/api/v1/orgs/%s", slug), nil, input, &org)
	if err != nil {
		return nil, err
	}
	return &org, nil
}

// DeleteOrg deletes an organization by slug.
func (c *Client) DeleteOrg(ctx context.Context, slug string) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/orgs/%s", slug), nil, nil, nil)
}

// AddMember adds a user to an organization.
func (c *Client) AddMember(ctx context.Context, slug string, input AddMemberInput) (*OrgMember, error) {
	var member OrgMember
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/orgs/%s/members", slug), nil, input, &member)
	if err != nil {
		return nil, err
	}
	return &member, nil
}

// RemoveMember removes a user from an organization.
func (c *Client) RemoveMember(ctx context.Context, slug, userID string) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/orgs/%s/members/%s", slug, userID), nil, nil, nil)
}

// memberListResponse matches the server's JSON envelope for member lists.
type memberListResponse struct {
	Data []OrgMember `json:"data"`
}

// ListMembers returns all members of an organization.
func (c *Client) ListMembers(ctx context.Context, slug string) ([]OrgMember, error) {
	var resp memberListResponse
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/orgs/%s/members", slug), nil, nil, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// UpdateMemberRole changes a member's role in an organization.
func (c *Client) UpdateMemberRole(ctx context.Context, slug, userID string, input UpdateMemberRoleInput) (*OrgMember, error) {
	var member OrgMember
	err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/api/v1/orgs/%s/members/%s", slug, userID), nil, input, &member)
	if err != nil {
		return nil, err
	}
	return &member, nil
}
