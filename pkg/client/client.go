// Package client provides a Go client for the seki Admin API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client is a seki Admin API client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets a custom *http.Client for the API client.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		cl.httpClient = c
	}
}

// New creates a new seki Admin API client.
// baseURL is the root URL of the seki server (e.g. "http://localhost:8080").
// apiKey is the API key used for authentication.
func New(baseURL, apiKey string, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: http.DefaultClient,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// do executes an HTTP request against the Admin API.
// method and path define the request. body is JSON-encoded as the request body
// (nil means no body). result, if non-nil, is decoded from the JSON response.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, result interface{}) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read the full response body.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	// Check for error responses (4xx, 5xx).
	if resp.StatusCode >= 400 {
		apiErr := &APIError{Status: resp.StatusCode}
		if len(data) > 0 {
			// Try to parse RFC 7807 problem detail.
			_ = json.Unmarshal(data, apiErr)
		}
		// Ensure status is always set from the HTTP response.
		apiErr.Status = resp.StatusCode
		if apiErr.Title == "" {
			apiErr.Title = http.StatusText(resp.StatusCode)
		}
		return apiErr
	}

	// 204 No Content — nothing to decode.
	if resp.StatusCode == http.StatusNoContent || result == nil {
		return nil
	}

	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
