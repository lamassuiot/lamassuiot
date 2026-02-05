package subsystem

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	postgres_test "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/test"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/subsystems"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.Postgres, &PostgresSubsystem{})
}

type PostgresSubsystem struct {
	schemas []string
}

func (p *PostgresSubsystem) Prepare(schemas []string) error {
	p.schemas = schemas
	return nil
}

func (p *PostgresSubsystem) Run(exposeAsStandardPort bool) (*subsystems.SubsystemBackend, error) {
	pConfig, postgresEngine := postgres_test.BeforeSuite(p.schemas, exposeAsStandardPort)
	configMap, err := config.EncodeStruct(pConfig)
	if err != nil {
		return nil, fmt.Errorf("could not encode postgres config: %s", err)
	}

	config := config.PluggableStorageEngine{LogLevel: config.Info, Provider: config.Postgres, Config: configMap}
	logger := helpers.SetupLogger(config.LogLevel, "storage", "postgres")

	for _, schemaName := range p.schemas {
		m := postgres.NewMigrator(logger, postgresEngine.DB[schemaName])
		m.MigrateToLatest()
	}

	beforeEach := func() error {
		for _, schemaName := range p.schemas {
			postgresEngine.BeforeEach()
			switch schemaName {
			case "ca":
				_, err := postgres.NewCAPostgresRepository(logger, postgresEngine.DB[schemaName])
				if err != nil {
					return fmt.Errorf("could not run reinitialize CA tables: %s", err)
				}

				_, err = postgres.NewCertificateRepository(logger, postgresEngine.DB[schemaName])
				if err != nil {
					return fmt.Errorf("could not run reinitialize Certificates tables: %s", err)
				}

			case "devicemanager":
				_, err := postgres.NewDeviceManagerRepository(logger, postgresEngine.DB[schemaName])
				if err != nil {
					return fmt.Errorf("could not run reinitialize DeviceManager tables: %s", err)
				}
			case "dmsmanager":
				_, err := postgres.NewDMSManagerRepository(logger, postgresEngine.DB[schemaName])
				if err != nil {
					return fmt.Errorf("could not run reinitialize DMSManager tables: %s", err)
				}
			case "va":
				_, err := postgres.NewVARepository(logger, postgresEngine.DB[schemaName])
				if err != nil {
					return fmt.Errorf("could not run reinitialize VA tables: %s", err)
				}
			case "kms":
				_, err := postgres.NewKMSPostgresRepository(logger, postgresEngine.DB[schemaName])
				if err != nil {
					return fmt.Errorf("could not run reinitialize KMS tables: %s", err)
				}
			default:
				return fmt.Errorf("unknown schema name: %s", schemaName)
			}
		}
		return nil
	}

	return &subsystems.SubsystemBackend{
		Config:     config,
		BeforeEach: beforeEach,
		AfterSuite: postgresEngine.AfterSuite,
	}, nil

}
