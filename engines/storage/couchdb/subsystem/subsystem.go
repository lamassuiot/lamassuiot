//go:build experimental

package subsystem

import (
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/test/subsystems"
	couchdb_test "github.com/lamassuiot/lamassuiot/v3/engines/storage/couchdb/test"
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

	config := config.PluggableStorageEngine{LogLevel: config.Info, Provider: config.CouchDB, CouchDB: *cconfig}

	beforeEach := func() error {
		return nil
	}

	return &subsystems.SubsystemBackend{
		Config:     config,
		BeforeEach: beforeEach,
		AfterSuite: func() { cleaner() },
	}, nil

}
