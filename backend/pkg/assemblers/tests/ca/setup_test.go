package ca

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
		WithDatabase("ca", "kms").
		WithVault().
		WithCascadeDelete(true).
		BuildSuite()
	if err != nil {
		log.Fatalf("could not create CA test server: %s", err)
	}

	code := m.Run()
	serverTest.AfterSuite()
	os.Exit(code)
}
