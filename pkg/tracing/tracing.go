// Package tracing wires OpenTelemetry distributed tracing for BSVM.
//
// # Scope
//
// This package handles **traces only**. Metrics are served via
// Prometheus (pkg/metrics) at /metrics. Splitting the two lets
// Grafana and Jaeger / Tempo scrape each at their native seam without
// dragging the whole OTel metrics SDK into the RPC hot path.
//
// # Configuration
//
// OTel reads standard environment variables when `Setup` is called:
//
//   - OTEL_EXPORTER_OTLP_ENDPOINT — e.g. "http://localhost:4318".
//     When unset, traces are emitted to stdout (dev-friendly).
//     When set to the literal string "disabled", no exporter is
//     created and Tracer() returns a no-op.
//   - OTEL_EXPORTER_OTLP_HEADERS — comma-separated key=value pairs
//     attached to every OTLP HTTP request (e.g. Honeycomb token).
//   - OTEL_SERVICE_NAME — service name on the resource (default
//     "bsvm").
//   - OTEL_RESOURCE_ATTRIBUTES — extra resource attributes in the
//     standard key=value,key=value format; these are merged with the
//     BSVM-injected node_name and chain_id attributes.
//
// # Usage
//
//	shutdown, err := tracing.Setup(ctx, tracing.Config{
//	    NodeName: "node1",
//	    ChainID:  "31337",
//	})
//	if err != nil { ... }
//	defer shutdown(context.Background())
//
//	tracer := tracing.Tracer("prover")
//	ctx, span := tracer.Start(ctx, "prove-batch")
//	defer span.End()
//
// Using otel.Tracer directly works too — Setup sets the global
// TracerProvider so any package that imports go.opentelemetry.io/otel
// gets the same pipeline.
package tracing

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Config drives the OTel tracer setup. NodeName and ChainID become
// resource attributes so distributed traces can be filtered per node
// or per shard in Jaeger / Tempo / Honeycomb.
type Config struct {
	// NodeName identifies the node within a shard. Becomes the
	// "bsvm.node_name" resource attribute.
	NodeName string
	// ChainID is the decimal-stringified L2 chain ID. Becomes the
	// "bsvm.chain_id" resource attribute.
	ChainID string
	// ServiceVersion is the BSVM release (e.g. "0.1.0"). Becomes the
	// "service.version" resource attribute.
	ServiceVersion string
}

// ShutdownFunc flushes in-flight spans and closes the exporter. The
// BSVM node defers this during graceful shutdown.
type ShutdownFunc func(context.Context) error

// noopShutdown is returned when tracing is disabled or the setup failed
// soft (in which case the global tracer provider is a no-op).
func noopShutdown(_ context.Context) error { return nil }

// Setup configures the global OpenTelemetry TracerProvider based on
// standard OTEL_* env vars. On success it returns a ShutdownFunc the
// caller MUST defer. On a non-fatal misconfiguration it logs a warning
// and returns a no-op shutdown — tracing is best-effort and must never
// prevent the node from running.
func Setup(ctx context.Context, cfg Config) (ShutdownFunc, error) {
	// "disabled" means skip exporter wiring entirely — useful for
	// tests and the minimal-ops case. The global TracerProvider stays
	// at the SDK default, which is a no-op.
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if endpoint == "disabled" {
		otel.SetTracerProvider(noop.NewTracerProvider())
		return noopShutdown, nil
	}

	res, err := buildResource(ctx, cfg)
	if err != nil {
		return noopShutdown, fmt.Errorf("building OTel resource: %w", err)
	}

	exporter, err := buildExporter(ctx, endpoint)
	if err != nil {
		// Downgrade to no-op so the node still starts. Tracing is an
		// observability add-on; a misconfigured exporter shouldn't
		// take the node down.
		slog.Warn("tracing: exporter unavailable, disabling traces", "error", err)
		otel.SetTracerProvider(noop.NewTracerProvider())
		return noopShutdown, nil
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	slog.Info("tracing: OTel tracer initialised",
		"endpoint", endpointDescription(endpoint),
		"service", resolveServiceName(),
	)

	return tp.Shutdown, nil
}

// Tracer returns a named tracer from the global TracerProvider. Callers
// can also use otel.Tracer("...") directly — the two return the same
// thing.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

// buildExporter picks an exporter backend based on
// OTEL_EXPORTER_OTLP_ENDPOINT:
//
//   - empty → stdout exporter (pretty JSON to stderr). Dev default so
//     operators see traces without needing a collector.
//   - http(s) → OTLP/HTTP exporter.
//
// gRPC OTLP is intentionally not wired in this helper — HTTP is the
// broadest-compatibility option and operators needing gRPC can swap the
// exporter themselves.
func buildExporter(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error) {
	if endpoint == "" {
		return stdouttrace.New(
			stdouttrace.WithPrettyPrint(),
			stdouttrace.WithoutTimestamps(),
		)
	}
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(endpoint),
	}
	if strings.HasPrefix(endpoint, "http://") {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if hdrs := otlpHeadersFromEnv(); len(hdrs) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(hdrs))
	}
	client := otlptracehttp.NewClient(opts...)
	return otlptrace.New(ctx, client)
}

// buildResource constructs the OTel resource describing this node
// process. Standard service.* attributes come from env; BSVM-specific
// node_name / chain_id are injected from cfg.
func buildResource(ctx context.Context, cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(resolveServiceName()),
	}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.ServiceVersion))
	}
	if cfg.NodeName != "" {
		attrs = append(attrs,
			attribute.String("bsvm.node_name", cfg.NodeName),
			// Also set service.instance.id so Jaeger groups spans per node.
			semconv.ServiceInstanceID(cfg.NodeName),
		)
	}
	if cfg.ChainID != "" {
		attrs = append(attrs, attribute.String("bsvm.chain_id", cfg.ChainID))
	}
	return resource.New(ctx,
		resource.WithFromEnv(), // picks up OTEL_RESOURCE_ATTRIBUTES
		resource.WithTelemetrySDK(),
		resource.WithProcessRuntimeName(),
		resource.WithAttributes(attrs...),
	)
}

// resolveServiceName returns the OTel service name from env or a
// sensible default. OTel's own convention is `OTEL_SERVICE_NAME`.
func resolveServiceName() string {
	if n := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); n != "" {
		return n
	}
	return "bsvm"
}

// otlpHeadersFromEnv parses OTEL_EXPORTER_OTLP_HEADERS ("k1=v1,k2=v2")
// into the map form the OTLP HTTP exporter accepts.
func otlpHeadersFromEnv() map[string]string {
	raw := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"))
	if raw == "" {
		return nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func endpointDescription(endpoint string) string {
	if endpoint == "" {
		return "stdout"
	}
	return endpoint
}
