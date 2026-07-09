package va

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
		WithDatabase("ca", "va", "kms").
		WithService(tests.CA, tests.VA).
		WithMonitor().
		WithEventBus().
		BuildSuite()
	if err != nil {
		log.Fatalf("could not create VA test server: %s", err)
	}

	code := m.Run()
	serverTest.AfterSuite()
	os.Exit(code)
}

func StartVAServiceTestServer(t *testing.T) (*tests.VATestServer, error) {
	if err := serverTest.BeforeEach(); err != nil {
		return nil, fmt.Errorf("could not run BeforeEach: %s", err)
	}
	return serverTest.VA, nil
}
