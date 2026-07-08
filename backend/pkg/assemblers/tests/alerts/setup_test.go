package alerts

import (
	"log"
	"os"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
)

var serverTest *tests.TestServer

func TestMain(m *testing.M) {
	var err error
	serverTest, err = tests.TestServiceBuilder{}.
		WithDatabase("ca", "alerts", "kms").
		WithService(tests.ALERTS).
		BuildSuite()
	if err != nil {
		log.Fatalf("could not create Alerts test server: %s", err)
	}

	code := m.Run()
	serverTest.AfterSuite()
	os.Exit(code)
}
