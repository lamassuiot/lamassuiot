package config

type LamassuMonolithicAssembleMode string

const (
	//all Lamassu service but the proxy server are deployed in memory. If services interact between them,
	//they do so by using each other's Business Logic (aka Service).
	InMemory LamassuMonolithicAssembleMode = "IN_MEMORY"
	//each Lamassu service is deployed as separate HTTP servers. If services interact between them, HTTP clients (SDKs) are used
	Http LamassuMonolithicAssembleMode = "HTTP"
)

type MonolithicConfig struct {
	BaseConfig       `mapstructure:",squash"`
	Storage          PluggableStorageEngine        `mapstructure:"storage"`
	CryptoEngines    CryptoEngines                 `mapstructure:"crypto_engines"`
	CryptoMonitoring CryptoMonitoring              `mapstructure:"crypto_monitoring"`
	Domain           string                        `mapstructure:"domain"`
	AssemblyMode     LamassuMonolithicAssembleMode `mapstructure:"assembly_mode"`
	GatewayPort      int                           `mapstructure:"gateway_port"`
}
