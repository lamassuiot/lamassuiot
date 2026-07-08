package devicemanager

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
		BuildSuite()
	if err != nil {
		log.Fatalf("could not create Device Manager test server: %s", err)
	}

	code := m.Run()
	serverTest.AfterSuite()
	os.Exit(code)
}

func StartDeviceManagerServiceTestServer(t *testing.T) (*tests.DeviceManagerTestServer, *tests.TestServer, error) {
	if err := serverTest.BeforeEach(); err != nil {
		return nil, nil, fmt.Errorf("could not run BeforeEach: %s", err)
	}
	return serverTest.DeviceManager, serverTest, nil
}
