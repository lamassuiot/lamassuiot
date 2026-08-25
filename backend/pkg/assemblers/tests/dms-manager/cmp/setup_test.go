package cmp

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
)

// serverTest is built once per test binary by TestMain and shared across all
// CMP tests in this package, mirroring the dms-manager package's own
// TestMain/StartDMSManagerServiceTestServer pattern. It cannot simply be
// imported from the dms-manager package: Go test binaries are compiled and
// run per-package, so a TestMain-built singleton in one package's test
// binary is never visible to another package's test binary.
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

// StartDMSManagerServiceTestServer resets per-test state (BeforeEach) against
// the suite-wide server built by TestMain and returns it for use in a single
// test.
func StartDMSManagerServiceTestServer(t *testing.T) (*tests.DMSManagerTestServer, *tests.TestServer, error) {
	t.Helper()
	if err := serverTest.BeforeEach(); err != nil {
		return nil, nil, fmt.Errorf("could not run BeforeEach: %s", err)
	}
	return serverTest.DMSManager, serverTest, nil
}
