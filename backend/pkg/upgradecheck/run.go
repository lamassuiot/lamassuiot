package upgradecheck

import (
	"context"
	"fmt"
	"io"

	bconfig "github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	lconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	"github.com/sirupsen/logrus"
)

// RunWithConfig runs every check against the database and the crypto engines of the KMS config, prints the report
// to w, and returns the exit code (see ExitCode). It returns 2 without running the checks when the database cannot
// be read or is not a 3.8 one.
func RunWithConfig(ctx context.Context, logger *logrus.Entry, conf bconfig.KMSConfig, w io.Writer) int {
	// The config is decoded here instead of building the storage engine, whose builder registers the GORM plugins
	// of the services: this command only needs plain connections.
	if conf.Storage.Provider != cconfig.Postgres {
		fmt.Fprintf(w, "unsupported storage provider %q: only postgres is supported\n", conf.Storage.Provider)
		return 2
	}
	pg, err := cconfig.DecodeStruct[lconfig.PostgresPSEConfig](conf.Storage.Config)
	if err != nil {
		fmt.Fprintf(w, "could not decode the postgres storage config: %s\n", err)
		return 2
	}

	env := NewEnv(logger, pg)
	if err := CheckV38Database(ctx, env); err != nil {
		fmt.Fprintf(w, "%s\n", err)
		return 2
	}

	checks := append([]Check{CryptoEnginesCheck(logger, conf.CryptoEngineConfig)}, VAChecks()...)
	results := RunChecks(ctx, env, checks)
	Report(w, results)
	return ExitCode(results)
}
