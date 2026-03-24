package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// HTTPRequestsTotal counts all HTTP requests by method, path, and status.
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "seki_http_requests_total",
			Help: "Total HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	// HTTPRequestDuration observes HTTP request duration in seconds.
	HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "seki_http_request_duration_seconds",
			Help:    "HTTP request duration",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// AuthAttemptsTotal counts authentication attempts by method and result.
	AuthAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "seki_auth_attempts_total",
			Help: "Authentication attempts",
		},
		[]string{"method", "result"}, // method: passkey/totp/password/social, result: success/failure
	)

	// TokenIssuedTotal counts tokens issued by grant type.
	TokenIssuedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "seki_token_issued_total",
			Help: "Tokens issued",
		},
		[]string{"grant_type"},
	)

	// ActiveSessions tracks the number of currently active sessions.
	ActiveSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "seki_active_sessions",
			Help: "Currently active sessions",
		},
	)
)

// Register registers all metrics with the default Prometheus registerer.
func Register() {
	prometheus.MustRegister(
		HTTPRequestsTotal,
		HTTPRequestDuration,
		AuthAttemptsTotal,
		TokenIssuedTotal,
		ActiveSessions,
	)
}
