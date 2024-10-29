package helpers

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
)

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

	logger = logrus.NewEntry(logrus.New())
	logger.Logger.Level = logrus.TraceLevel

	result = configureLoggerWithRequestID(ctx, logger)

	// Verify that the returned logger is not the same as the input logger
	if result == logger {
		t.Error("ConfigureLoggerWithRequestID returned a different logger when level is not TraceLevel or DebugLevel")
	}

	// Test case 2: Request ID exists in the context
	reqID := "12345"
	ctx = context.WithValue(ctx, "req-id", reqID)

	result = configureLoggerWithRequestID(ctx, logger)

	// Verify that the returned logger has the correct request ID field
	if result.Data["req-id"] != reqID {
		t.Errorf("ConfigureLoggerWithRequestID returned logger with incorrect request ID field. Expected: %s, Got: %v", reqID, result.Data["req-id"])
	}

	// Test case 3: Request ID does not exist in the context
	ctx = context.Background()

	result = configureLoggerWithRequestID(ctx, logger)

	// Verify that the returned logger has a generated request ID field
	if _, ok := result.Data["req-id"]; !ok {
		t.Error("ConfigureLoggerWithRequestID returned logger without request ID field")
	}

	// Verify that the generated request ID field starts with "unset."
	if reqID, ok := result.Data["req-id"].(string); ok {
		if !startsWith(reqID, "unset.") {
			t.Errorf("ConfigureLoggerWithRequestID returned logger with incorrect generated request ID field. Expected: %s, Got: %s", "unset.", reqID)
		}
	} else {
		t.Error("ConfigureLoggerWithRequestID returned logger with incorrect generated request ID field type")
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
