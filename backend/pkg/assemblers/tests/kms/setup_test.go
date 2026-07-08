package kms

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
		WithDatabase("kms", "ca").
		WithVault().
		BuildSuite()
	if err != nil {
		log.Fatalf("could not create KMS test server: %s", err)
	}

	code := m.Run()
	serverTest.AfterSuite()
	os.Exit(code)
}

func StartKMSServiceTestServer(t *testing.T) (*tests.KMSTestServer, error) {
	if err := serverTest.BeforeEach(); err != nil {
		return nil, fmt.Errorf("could not run BeforeEach: %s", err)
	}
	return serverTest.KMS, nil
}
