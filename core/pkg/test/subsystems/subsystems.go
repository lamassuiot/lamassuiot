package subsystems

type SubsystemBackend struct {
	Config     interface{}
	Extra      *map[string]interface{}
	BeforeEach func() error
	AfterSuite func()
}

type Subsystem interface {
	Run() (*SubsystemBackend, error)
}

type StorageSubsystem interface {
	Subsystem
	Prepare(dbs []string) error
}

type ParametrizedSubsystem interface {
	Subsystem
	Preare(config map[string]interface{}) error
}

type SubsystemProvider string

const (
	Postgres SubsystemProvider = "postgres"
	CouchDB  SubsystemProvider = "couchdb"
	RabbitMQ SubsystemProvider = "rabbitmq"
	Vault    SubsystemProvider = "vault"
	Pkcs11   SubsystemProvider = "pkcs11"
	Aws      SubsystemProvider = "aws"
)

var subsystemsMap map[SubsystemProvider]Subsystem = make(map[SubsystemProvider]Subsystem)

func RegisterSubsystemBuilder(name SubsystemProvider, subsystem Subsystem) {
	subsystemsMap[name] = subsystem
}

func GetSubsystemBuilder[E Subsystem](name SubsystemProvider) E {
	return subsystemsMap[name].(E)
}
