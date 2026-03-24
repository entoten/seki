package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// User represents a seki user.
type User struct {
	ID            string          `json:"id"`
	Email         string          `json:"email"`
	DisplayName   string          `json:"display_name"`
	Disabled      bool            `json:"disabled"`
	EmailVerified bool            `json:"email_verified"`
	Metadata      json.RawMessage `json:"metadata"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// CreateUserInput is the input for creating a user.
type CreateUserInput struct {
	Email       string          `json:"email"`
	DisplayName string          `json:"display_name"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

// UpdateUserInput is the input for updating a user.
type UpdateUserInput struct {
	Email       *string          `json:"email,omitempty"`
	DisplayName *string          `json:"display_name,omitempty"`
	Disabled    *bool            `json:"disabled,omitempty"`
	Metadata    *json.RawMessage `json:"metadata,omitempty"`
}

// CreateUser creates a new user.
func (c *Client) CreateUser(ctx context.Context, input CreateUserInput) (*User, error) {
	var user User
	err := c.do(ctx, http.MethodPost, "/api/v1/users", nil, input, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUser retrieves a user by ID.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	var user User
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/users/%s", id), nil, nil, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// userListResponse matches the server's JSON shape for user lists,
// which uses "users" instead of "data".
type userListResponse struct {
	Users      []User `json:"users"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// ListUsers returns a paginated list of users.
func (c *Client) ListUsers(ctx context.Context, opts ListOptions) (*ListResult[User], error) {
	var resp userListResponse
	err := c.do(ctx, http.MethodGet, "/api/v1/users", opts.queryParams(), nil, &resp)
	if err != nil {
		return nil, err
	}
	return &ListResult[User]{
		Data:       resp.Users,
		NextCursor: resp.NextCursor,
	}, nil
}

// UpdateUser updates an existing user.
func (c *Client) UpdateUser(ctx context.Context, id string, input UpdateUserInput) (*User, error) {
	var user User
	err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/api/v1/users/%s", id), nil, input, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// DeleteUser deletes a user by ID.
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/users/%s", id), nil, nil, nil)
}
