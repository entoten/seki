package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Monet/seki/internal/metrics"
)

// setup creates a fresh registry and re-registers the metrics so tests are
// isolated from each other and from any global registration done elsewhere.
func setup(t *testing.T) {
	t.Helper()
	// Reset the default registry so we start clean each test.
	reg := prometheus.NewRegistry()
	prometheus.DefaultRegisterer = reg
	prometheus.DefaultGatherer = reg
	metrics.ResetRegistration()
	metrics.Register()
}

func TestMiddleware_IncrementsRequestCounter(t *testing.T) {
	setup(t)

	handler := metrics.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	count := testutil.ToFloat64(metrics.HTTPRequestsTotal.WithLabelValues("GET", "/healthz", "200"))
	if count != 1 {
		t.Fatalf("expected request counter to be 1, got %v", count)
	}
}

func TestMiddleware_RecordsDurationHistogram(t *testing.T) {
	setup(t)

	handler := metrics.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Collect the histogram and verify it recorded an observation.
	count := testutil.CollectAndCount(metrics.HTTPRequestDuration)
	if count == 0 {
		t.Fatal("expected duration histogram to have observations, got none")
	}
}

func TestMetricsEndpoint_ReturnsPrometheusFormat(t *testing.T) {
	setup(t)

	// Bump a counter so we have at least one metric line.
	metrics.HTTPRequestsTotal.WithLabelValues("GET", "/test", "200").Inc()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "seki_http_requests_total") {
		t.Fatalf("expected metrics output to contain seki_http_requests_total, got:\n%s", body)
	}
	if !strings.Contains(body, "seki_http_request_duration_seconds") {
		t.Fatalf("expected metrics output to contain seki_http_request_duration_seconds, got:\n%s", body)
	}
}

func TestNormalizePath_ReplacesUUIDs(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/users/550e8400-e29b-41d4-a716-446655440000", "/users/{id}"},
		{"/users/550e8400-e29b-41d4-a716-446655440000/sessions", "/users/{id}/sessions"},
		{"/healthz", "/healthz"},
	}

	for _, tt := range tests {
		got := metrics.NormalizePath(tt.input)
		if got != tt.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizePath_ReplacesNumericIDs(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/users/42", "/users/{id}"},
		{"/users/42/roles", "/users/{id}/roles"},
		{"/orgs/123/members/456", "/orgs/{id}/members/{id}"},
	}

	for _, tt := range tests {
		got := metrics.NormalizePath(tt.input)
		if got != tt.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
