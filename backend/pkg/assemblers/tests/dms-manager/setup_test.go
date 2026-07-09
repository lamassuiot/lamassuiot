package dmsmanager

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
)

var serverTest *tests.TestServer

func TestMain(m *testing.M) {
	var err error
	serverTest, err = tests.TestServiceBuilder{}.
		WithDatabase("ca", "devicemanager", "dmsmanager", "kms").
		WithService(tests.CA, tests.DEVICE_MANAGER, tests.DMS_MANAGER).
		WithEventBus().
		BuildSuite()
	if err != nil {
		log.Fatalf("could not create DMS Manager test server: %s", err)
	}

	code := m.Run()
	serverTest.AfterSuite()
	os.Exit(code)
}

func StartDMSManagerServiceTestServer(t *testing.T) (*tests.DMSManagerTestServer, *tests.TestServer, error) {
	if err := serverTest.BeforeEach(); err != nil {
		return nil, nil, fmt.Errorf("could not run BeforeEach: %s", err)
	}
	return serverTest.DMSManager, serverTest, nil
}
