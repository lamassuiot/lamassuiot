package pkg

import "github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/monoconfig"

// Alias de compatibilidad: la configuración vive en pkg/monoconfig.
type (
	LamassuMonolithicAssembleMode = monoconfig.LamassuMonolithicAssembleMode
	MonolithicConfig              = monoconfig.MonolithicConfig
	MonolithicAWSIoTManagerConfig = monoconfig.MonolithicAWSIoTManagerConfig
)

const (
	InMemory = monoconfig.InMemory
	Http     = monoconfig.Http
)
