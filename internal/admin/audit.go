package admin

import (
	"net/http"
	"strconv"

	"github.com/Monet/seki/internal/storage"
)

func (h *Handler) registerAuditRoutesOn(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/audit-logs", h.handleListAuditLogs)
}

func (h *Handler) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := 50
	if l := q.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	opts := storage.AuditListOptions{
		Cursor:  q.Get("cursor"),
		Limit:   limit,
		ActorID: q.Get("actor_id"),
		Action:  q.Get("action"),
	}

	entries, nextCursor, err := h.store.ListAuditLogs(r.Context(), opts)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}

	type response struct {
		Data       []*storage.AuditEntry `json:"data"`
		NextCursor string                `json:"next_cursor,omitempty"`
	}

	if entries == nil {
		entries = []*storage.AuditEntry{}
	}

	writeJSON(w, http.StatusOK, response{Data: entries, NextCursor: nextCursor})
}
