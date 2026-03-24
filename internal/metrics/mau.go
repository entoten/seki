package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Monet/seki/internal/storage"
)

var (
	// MAUTotal tracks the total monthly active users.
	MAUTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "seki_mau_total",
			Help: "Total monthly active users",
		},
	)

	// MAUByOrg tracks monthly active users per organization.
	MAUByOrg = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "seki_mau_by_org",
			Help: "Monthly active users by organization",
		},
		[]string{"org"},
	)

	mauRegistered bool
)

// RegisterMAU registers the MAU metrics with the default Prometheus registerer.
func RegisterMAU() {
	mu.Lock()
	defer mu.Unlock()
	if mauRegistered {
		return
	}
	prometheus.MustRegister(MAUTotal, MAUByOrg)
	mauRegistered = true
}

// ResetMAURegistration clears the MAU registration flag. Intended for tests only.
func ResetMAURegistration() {
	mu.Lock()
	defer mu.Unlock()
	mauRegistered = false
}

// MAUTracker provides monthly active user metrics from audit logs.
type MAUTracker struct {
	store storage.Storage
}

// NewMAUTracker creates a new MAU tracker.
func NewMAUTracker(store storage.Storage) *MAUTracker {
	return &MAUTracker{store: store}
}

// GetMAU returns the number of distinct users who logged in during the given month.
func (t *MAUTracker) GetMAU(ctx context.Context, month time.Time) (int, error) {
	from, to := monthRange(month)
	return t.store.CountDistinctActors(ctx, "user.login", from, to)
}

// GetMAUByOrg returns the number of distinct users in an org who logged in during the given month.
func (t *MAUTracker) GetMAUByOrg(ctx context.Context, month time.Time, orgID string) (int, error) {
	from, to := monthRange(month)
	return t.store.CountDistinctActorsByOrg(ctx, "user.login", from, to, orgID)
}

// GetMAUHistory returns the MAU count for the last N months, most recent first.
func (t *MAUTracker) GetMAUHistory(ctx context.Context, months int) ([]MAUHistoryEntry, error) {
	if months <= 0 {
		months = 6
	}
	now := time.Now().UTC()
	entries := make([]MAUHistoryEntry, 0, months)
	for i := 0; i < months; i++ {
		month := time.Date(now.Year(), now.Month()-time.Month(i), 1, 0, 0, 0, 0, time.UTC)
		count, err := t.GetMAU(ctx, month)
		if err != nil {
			return nil, err
		}
		entries = append(entries, MAUHistoryEntry{
			Month: month.Format("2006-01"),
			MAU:   count,
		})
	}
	return entries, nil
}

// UpdatePrometheusGauges updates the MAU Prometheus gauges.
func (t *MAUTracker) UpdatePrometheusGauges(ctx context.Context) {
	now := time.Now().UTC()
	count, err := t.GetMAU(ctx, now)
	if err == nil {
		MAUTotal.Set(float64(count))
	}
}

// MAUHistoryEntry represents a single month's MAU count.
type MAUHistoryEntry struct {
	Month string `json:"month"`
	MAU   int    `json:"mau"`
}

// monthRange returns the start (inclusive) and end (exclusive) of the given month.
func monthRange(month time.Time) (time.Time, time.Time) {
	from := time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	return from, to
}
