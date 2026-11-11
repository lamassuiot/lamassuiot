package store

import (
	"fmt"
	"os"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/testutil"
)

func TestMain(m *testing.M) {
	exitCode := m.Run()
	if err := testutil.CleanupOracleTestDatabase(); err != nil {
		fmt.Fprintf(os.Stderr, "clean up Authz Oracle test database: %v\n", err)
		if exitCode == 0 {
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}
