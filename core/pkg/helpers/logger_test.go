package helpers

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"
)

// mockSpan implements trace.Span for testing
type mockSpan struct {
	trace.Span
	spanContext trace.SpanContext
}

func (m *mockSpan) SpanContext() trace.SpanContext {
	return m.spanContext
}

func (m *mockSpan) End(...trace.SpanEndOption) {}

func TestConfigureLoggerWithRequestID(t *testing.T) {
	// Test case 1: Logger level is not TraceLevel or DebugLevel
	logger := logrus.NewEntry(logrus.New())
	logger.Logger.Level = logrus.InfoLevel
	ctx := context.Background()

	result := configureLoggerWithRequestID(ctx, logger)

	// Verify that the returned logger is the same as the input logger
	if result != logger {
		t.Error("ConfigureLoggerWithRequestID returned a different logger when level is not TraceLevel DebugLevel")
	}

	// Test case 2: Logger level is TraceLevel with no trace ID
	logger = logrus.NewEntry(logrus.New())
	logger.Logger.Level = logrus.TraceLevel

	result = configureLoggerWithRequestID(ctx, logger)

	// Verify that the returned logger is the same as input (no trace ID in context)
	if result != logger {
		t.Error("ConfigureLoggerWithRequestID returned a different logger when no trace ID exists")
	}

	// Test case 3: Trace ID exists in the context
	logger = logrus.NewEntry(logrus.New())
	logger.Logger.Level = logrus.DebugLevel

	// Create a mock span with a valid trace ID
	traceID, _ := trace.TraceIDFromHex("1234567890abcdef1234567890abcdef")
	spanID, _ := trace.SpanIDFromHex("1234567890abcdef")
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})

	mockSpan := &mockSpan{spanContext: spanContext}
	ctx = trace.ContextWithSpan(context.Background(), mockSpan)

	result = configureLoggerWithRequestID(ctx, logger)

	// Verify that the returned logger has the trace-id field
	if _, ok := result.Data["trace-id"]; !ok {
		t.Error("ConfigureLoggerWithRequestID returned logger without trace-id field")
	}

	// Verify that the trace-id field is a valid string
	if traceIDStr, ok := result.Data["trace-id"].(string); ok {
		expectedTraceID := traceID.String()
		if traceIDStr != expectedTraceID {
			t.Errorf("ConfigureLoggerWithRequestID returned logger with incorrect trace ID. Expected: %s, Got: %s", expectedTraceID, traceIDStr)
		}
	} else {
		t.Error("ConfigureLoggerWithRequestID returned logger with incorrect trace-id field type")
	}
}
