package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/entoten/seki/internal/metrics"
	"github.com/entoten/seki/internal/storage"
)

// registerMAURoutesOn registers MAU metrics API routes on the given mux.
func (h *Handler) registerMAURoutesOn(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/metrics/mau", h.handleGetMAU)
	mux.HandleFunc("GET /api/v1/metrics/mau/history", h.handleGetMAUHistory)
}

func (h *Handler) handleGetMAU(w http.ResponseWriter, r *http.Request) {
	tracker := metrics.NewMAUTracker(h.store)
	now := time.Now().UTC()

	orgSlug := r.URL.Query().Get("org")
	if orgSlug != "" {
		org, err := h.store.GetOrgBySlug(r.Context(), orgSlug)
		if err != nil {
			if err == storage.ErrNotFound {
				writeProblem(w, r, http.StatusNotFound, ErrCodeOrgNotFound, "organization not found")
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to get organization")
			return
		}

		count, err := tracker.GetMAUByOrg(r.Context(), now, org.ID)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to get MAU")
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mau":   count,
			"month": now.Format("2006-01"),
			"org":   orgSlug,
		})
		return
	}

	count, err := tracker.GetMAU(r.Context(), now)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to get MAU")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mau":   count,
		"month": now.Format("2006-01"),
	})
}

func (h *Handler) handleGetMAUHistory(w http.ResponseWriter, r *http.Request) {
	tracker := metrics.NewMAUTracker(h.store)

	months := 6
	if m := r.URL.Query().Get("months"); m != "" {
		if parsed, err := strconv.Atoi(m); err == nil && parsed > 0 && parsed <= 24 {
			months = parsed
		}
	}

	history, err := tracker.GetMAUHistory(r.Context(), months)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, ErrCodeInternalError, "failed to get MAU history")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": history,
	})
}
