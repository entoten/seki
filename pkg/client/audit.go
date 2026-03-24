package client

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// AuditEntry represents a single audit log record.
type AuditEntry struct {
	ID         string          `json:"id"`
	ActorID    string          `json:"actor_id"`
	Action     string          `json:"action"`
	Resource   string          `json:"resource"`
	ResourceID string          `json:"resource_id"`
	IPAddress  string          `json:"ip_address"`
	UserAgent  string          `json:"user_agent"`
	Metadata   json.RawMessage `json:"metadata"`
	CreatedAt  time.Time       `json:"created_at"`
}

// AuditListOptions controls pagination and filtering for audit log queries.
type AuditListOptions struct {
	Cursor  string
	Limit   int
	ActorID string
	Action  string
}

// ListAuditLogs returns a paginated, optionally filtered list of audit entries.
func (c *Client) ListAuditLogs(ctx context.Context, opts AuditListOptions) (*ListResult[AuditEntry], error) {
	q := (ListOptions{Cursor: opts.Cursor, Limit: opts.Limit}).queryParams()
	if opts.ActorID != "" {
		q.Set("actor_id", opts.ActorID)
	}
	if opts.Action != "" {
		q.Set("action", opts.Action)
	}

	var resp ListResult[AuditEntry]
	err := c.do(ctx, http.MethodGet, "/api/v1/audit-logs", q, nil, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
