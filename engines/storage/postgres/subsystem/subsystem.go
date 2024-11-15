package subsystem

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/test/subsystems"
	"github.com/lamassuiot/lamassuiot/v3/engines/storage/postgres"
	postgres_test "github.com/lamassuiot/lamassuiot/v3/engines/storage/postgres/test"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.Postgres, &PostgresSubsystem{})
}

type PostgresSubsystem struct {
	dbs []string
}

func (p *PostgresSubsystem) Prepare(dbs []string) error {
	p.dbs = dbs
	return nil
}

func (p *PostgresSubsystem) Run() (*subsystems.SubsystemBackend, error) {

	pConfig, postgresEngine := postgres_test.BeforeSuite(p.dbs)
	config := config.PluggableStorageEngine{LogLevel: config.Info, Provider: config.Postgres, Postgres: pConfig}

	beforeEach := func() error {
		for _, dbName := range p.dbs {
			postgresEngine.BeforeEach()
			switch dbName {
			case "ca":
				_, err := postgres.NewCAPostgresRepository(postgresEngine.DB[dbName])
				if err != nil {
					return fmt.Errorf("could not run reinitialize CA tables: %s", err)
				}
			case "certificates":
				_, err := postgres.NewCertificateRepository(postgresEngine.DB[dbName])
				if err != nil {
					return fmt.Errorf("could not run reinitialize Certificates tables: %s", err)
				}
			case "devicemanager":
				_, err := postgres.NewDeviceManagerRepository(postgresEngine.DB[dbName])
				if err != nil {
					return fmt.Errorf("could not run reinitialize DeviceManager tables: %s", err)
				}
			case "dmsmanager":
				_, err := postgres.NewDMSManagerRepository(postgresEngine.DB[dbName])
				if err != nil {
					return fmt.Errorf("could not run reinitialize DMSManager tables: %s", err)
				}
			default:
				return fmt.Errorf("unknown db name: %s", dbName)
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
