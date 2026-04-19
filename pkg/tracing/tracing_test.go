package tracing

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
)

func TestSetup_DisabledProducesNoopProvider(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "disabled")

	shutdown, err := Setup(context.Background(), Config{
		NodeName: "node1",
		ChainID:  "31337",
	})
	if err != nil {
		t.Fatalf("Setup returned error with endpoint=disabled: %v", err)
	}
	defer func() {
		if err := shutdown(context.Background()); err != nil {
			t.Errorf("shutdown error: %v", err)
		}
	}()

	// With endpoint=disabled, the tracer must be the OTel no-op.
	tr := otel.Tracer("bsvm/test")
	_, span := tr.Start(context.Background(), "test-span")
	if span.SpanContext().IsSampled() {
		t.Error("no-op tracer should never produce sampled spans")
	}
	span.End()
}

func TestSetup_StdoutFallbackWhenUnset(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_SERVICE_NAME", "bsvm-test")

	shutdown, err := Setup(context.Background(), Config{
		NodeName:       "node1",
		ChainID:        "31337",
		ServiceVersion: "test",
	})
	if err != nil {
		t.Fatalf("Setup with empty endpoint should fall back to stdout, got %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected non-nil shutdown func")
	}
	// Emit a span so the stdout exporter gets exercised on shutdown.
	tr := otel.Tracer("bsvm/test")
	_, span := tr.Start(context.Background(), "stdout-span")
	span.End()
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown returned error: %v", err)
	}
}

func TestSetup_BadEndpointSoftFails(t *testing.T) {
	// A bogus URL must degrade to no-op instead of taking the node down.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "not-a-url://x")

	shutdown, err := Setup(context.Background(), Config{
		NodeName: "node1",
		ChainID:  "31337",
	})
	if err != nil {
		t.Fatalf("bad endpoint should not hard-fail Setup, got: %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected non-nil shutdown func even on soft fail")
	}
	_ = shutdown(context.Background())
}

func TestTracerAlwaysUsable(t *testing.T) {
	// Even without Setup, Tracer must return a non-nil tracer so
	// callers can safely construct spans at package init time.
	tr := Tracer("bsvm/test")
	if tr == nil {
		t.Fatal("Tracer returned nil")
	}
	_, span := tr.Start(context.Background(), "untouched-provider")
	span.End()
}

func TestOtlpHeadersFromEnv(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", " k1=v1 , k2=v 2 ,garbage,=leftempty")

	got := otlpHeadersFromEnv()
	if got["k1"] != "v1" {
		t.Errorf("k1: expected v1, got %q", got["k1"])
	}
	if got["k2"] != "v 2" {
		t.Errorf("k2: expected 'v 2', got %q", got["k2"])
	}
	if _, ok := got["garbage"]; ok {
		t.Error("'garbage' should be dropped (no '=' separator)")
	}
	if got[""] != "leftempty" {
		// empty key with a value should survive the parse even if it's
		// probably a bad input; we just verify our splitter doesn't
		// drop the value silently.
		t.Errorf("empty-key entry missing, got %q", got[""])
	}
}
