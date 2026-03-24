package client

import (
	"net/url"
	"strconv"
)

// ListOptions controls cursor-based pagination for list endpoints.
type ListOptions struct {
	Cursor string
	Limit  int
}

// ListResult is a paginated list response.
type ListResult[T any] struct {
	Data       []T    `json:"data"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// queryParams converts ListOptions to URL query parameters.
func (o ListOptions) queryParams() url.Values {
	q := url.Values{}
	if o.Cursor != "" {
		q.Set("cursor", o.Cursor)
	}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	return q
}
