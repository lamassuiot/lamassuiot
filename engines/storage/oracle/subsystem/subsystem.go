package subsystem

import (
	"context"
	"fmt"
	"time"

	coreconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/migrations"
	oracletest "github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/test"
	"github.com/lamassuiot/lamassuiot/v4/shared/subsystems/pkg/test/subsystems"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.Oracle, &OracleSubsystem{})
}

// OracleSubsystem uses one Oracle user schema for all Lamassu storage tables.
type OracleSubsystem struct{}

var _ subsystems.StorageSubsystem = (*OracleSubsystem)(nil)

// Prepare accepts the services requested by the shared test harness. Oracle's
// engine stores them in one user schema, so no per-service schema setup is
// necessary.
func (*OracleSubsystem) Prepare([]string) error { return nil }

func (*OracleSubsystem) Run(exposeAsStandardPort bool) (*subsystems.SubsystemBackend, error) {
	cfg, suite, err := oracletest.BeforeSuite(exposeAsStandardPort)
	if err != nil {
		return nil, fmt.Errorf("start Oracle test database: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := migrations.Apply(ctx, suite.DB, migrations.Plan()); err != nil {
		suite.AfterSuite()
		return nil, fmt.Errorf("migrate Oracle test database: %w", err)
	}

	configMap, err := coreconfig.EncodeStruct(cfg)
	if err != nil {
		suite.AfterSuite()
		return nil, fmt.Errorf("encode Oracle test configuration: %w", err)
	}
	storageConfig := coreconfig.PluggableStorageEngine{
		LogLevel: coreconfig.Info,
		Provider: coreconfig.Oracle,
		Config:   configMap,
	}
	return &subsystems.SubsystemBackend{
		Config:     storageConfig,
		BeforeEach: suite.BeforeEach,
		AfterSuite: suite.AfterSuite,
	}, nil
}
