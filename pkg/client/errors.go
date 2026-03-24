package client

import (
	"errors"
	"fmt"
	"net/http"
)

// APIError represents an RFC 7807 Problem Details error returned by the seki Admin API.
type APIError struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s: %s (HTTP %d)", e.Title, e.Detail, e.Status)
	}
	return fmt.Sprintf("%s (HTTP %d)", e.Title, e.Status)
}

// IsNotFound reports whether the error is a 404 Not Found API error.
func IsNotFound(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusNotFound
	}
	return false
}

// IsConflict reports whether the error is a 409 Conflict API error.
func IsConflict(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusConflict
	}
	return false
}
