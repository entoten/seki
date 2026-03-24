// Package telemetry provides OpenTelemetry tracing setup for Seki.
package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/entoten/seki/internal/config"
)

// Tracer returns the package-level tracer for instrumentation.
func Tracer() trace.Tracer {
	return otel.Tracer("github.com/entoten/seki")
}

// Setup configures the OpenTelemetry tracing pipeline.
// When cfg.Enabled is false it returns a no-op shutdown function and no error.
// The returned shutdown function should be called during graceful shutdown.
func Setup(cfg config.TelemetryConfig) (shutdown func(context.Context) error, err error) {
	noopShutdown := func(context.Context) error { return nil }

	if !cfg.Enabled {
		// Set a noop tracer provider so instrumentation calls are safe.
		otel.SetTracerProvider(noop.NewTracerProvider())
		return noopShutdown, nil
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "seki"
	}

	ctx := context.Background()

	opts := []otlptracehttp.Option{
		otlptracehttp.WithInsecure(),
	}
	if cfg.OTLPEndpoint != "" {
		opts = append(opts, otlptracehttp.WithEndpoint(cfg.OTLPEndpoint))
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return noopShutdown, fmt.Errorf("telemetry: create OTLP exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return noopShutdown, fmt.Errorf("telemetry: create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}

// SetupWithProvider sets a custom TracerProvider. This is useful for testing.
func SetupWithProvider(tp trace.TracerProvider) {
	otel.SetTracerProvider(tp)
}
