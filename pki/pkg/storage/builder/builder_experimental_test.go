package builder

import (
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	log "github.com/sirupsen/logrus"
)

func TestBuildStorageEngineUnknownMissing(t *testing.T) {
	logger := log.WithField("test", "BuildStorageEngine_InvalidProvider")
	conf := config.PluggableStorageEngine{
		Provider: "unkown",
	}

	// Call the BuildStorageEngine function
	_, err := BuildStorageEngine(logger, conf)

	// Verify the result
	if err == nil {
		t.Error("expected an error, but got nil")
	}

	if err.Error() != fmt.Sprintf("no storage engine of type %s", conf.Provider) {
		t.Errorf("unexpected error: %s", err)
	}
}
