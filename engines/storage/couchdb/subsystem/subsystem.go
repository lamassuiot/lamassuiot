//go:build experimental

package subsystem

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	couchdb_test "github.com/lamassuiot/lamassuiot/engines/storage/couchdb/v3/test"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/subsystems"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.CouchDB, &CouchDBSubsystem{})
}

type CouchDBSubsystem struct {
	dbs []string
}

func (p *CouchDBSubsystem) Prepare(dbs []string) error {
	p.dbs = dbs
	return nil
}

func (p *CouchDBSubsystem) Run() (*subsystems.SubsystemBackend, error) {

	cleaner, cconfig, err := couchdb_test.RunCouchDBDocker()
	if err != nil {
		return nil, err
	}

	config := config.PluggableStorageEngine{LogLevel: config.Info, Provider: config.CouchDB, Config: *cconfig}

	beforeEach := func() error {
		return nil
	}

	return &subsystems.SubsystemBackend{
		Config:     config,
		BeforeEach: beforeEach,
		AfterSuite: func() { cleaner() },
	}, nil

}
