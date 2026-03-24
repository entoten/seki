package telemetry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/entoten/seki/internal/config"
	"github.com/entoten/seki/internal/telemetry"
)

func TestSetup_Disabled(t *testing.T) {
	cfg := config.TelemetryConfig{
		Enabled: false,
	}
	shutdown, err := telemetry.Setup(cfg)
	if err != nil {
		t.Fatalf("Setup with disabled config should not error, got: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown should not error: %v", err)
	}
}

func TestHTTPMiddleware_AddsTraceIDHeader(t *testing.T) {
	// Set up an in-memory span exporter.
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	telemetry.SetupWithProvider(tp)
	defer tp.Shutdown(context.Background())

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := telemetry.HTTPMiddleware()(inner)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	traceID := rec.Header().Get(telemetry.TraceIDHeader)
	if traceID == "" {
		t.Fatal("expected X-Trace-ID header to be set, but it was empty")
	}

	// Verify a span was recorded.
	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span to be recorded")
	}

	found := false
	for _, s := range spans {
		if s.Name == "GET /healthz" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a span named 'GET /healthz', got spans: %v", spans)
	}
}

func TestHTTPMiddleware_SpansCreated(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	telemetry.SetupWithProvider(tp)
	defer tp.Shutdown(context.Background())

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	handler := telemetry.HTTPMiddleware()(inner)

	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected spans to be created for HTTP request")
	}

	// Verify the span has the expected attributes.
	span := spans[0]
	var foundMethod, foundRoute, foundStatus bool
	for _, attr := range span.Attributes {
		switch string(attr.Key) {
		case "http.method":
			if attr.Value.AsString() == "POST" {
				foundMethod = true
			}
		case "http.route":
			if attr.Value.AsString() == "/token" {
				foundRoute = true
			}
		case "http.status_code":
			if attr.Value.AsInt64() == 201 {
				foundStatus = true
			}
		}
	}

	if !foundMethod {
		t.Error("expected http.method=POST attribute on span")
	}
	if !foundRoute {
		t.Error("expected http.route=/token attribute on span")
	}
	if !foundStatus {
		t.Error("expected http.status_code=201 attribute on span")
	}
}
