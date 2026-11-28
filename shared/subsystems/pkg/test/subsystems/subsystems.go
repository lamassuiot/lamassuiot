package subsystems

import "sync"

type SubsystemBackend struct {
	Config     any
	Extra      *map[string]any
	BeforeEach func() error
	AfterSuite func()
}

type Subsystem interface {
	Run(exposeAsStandardPort bool) (*SubsystemBackend, error)
}

type StorageSubsystem interface {
	Subsystem
	Prepare(dbs []string) error
}

type ParametrizedSubsystem interface {
	Subsystem
	Prepare(config map[string]any) error
}

type SubsystemProvider string

const (
	Postgres SubsystemProvider = "postgres"
	Oracle   SubsystemProvider = "oracle"
	CouchDB  SubsystemProvider = "couchdb"
	RabbitMQ SubsystemProvider = "rabbitmq"
	Vault    SubsystemProvider = "vault"
	Pkcs11   SubsystemProvider = "pkcs11"
	Aws      SubsystemProvider = "aws"
	Azure    SubsystemProvider = "azure"
)

var (
	subsystemsMapMu sync.RWMutex
	subsystemsMap   = make(map[SubsystemProvider]Subsystem)
)

func RegisterSubsystemBuilder(name SubsystemProvider, subsystem Subsystem) {
	subsystemsMapMu.Lock()
	defer subsystemsMapMu.Unlock()

	subsystemsMap[name] = subsystem
}

func GetSubsystemBuilder[E Subsystem](name SubsystemProvider) E {
	subsystemsMapMu.RLock()
	subsystem := subsystemsMap[name]
	subsystemsMapMu.RUnlock()

	return subsystem.(E)
}
