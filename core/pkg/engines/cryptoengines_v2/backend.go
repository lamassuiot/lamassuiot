package cryptoenginesv2

import "context"

// Backend: where the private material actually lives.
type Backend interface {
	Name() string
	Capabilities() BackendCapabilities

	Generate(ctx context.Context, spec CreateKeySpec) (KeyHandle, error)
	Import(ctx context.Context, spec ImportKeySpec) (KeyHandle, error)
	Load(ctx context.Context, rec KeyRecord) (KeyHandle, error)
	Destroy(ctx context.Context, ref BackendRef) error
}

type BackendCapabilities struct {
	Algorithms  []AlgorithmID
	Operations  []Operation
	Extractable bool // can WrapKey export the material for BackupKey?
}

type BackendRef struct {
	Backend string // matches Backend.Name()
	URI     string // e.g. "pkcs11:slot=3;id=0xAB12", "soft:blob/abc"
}

// BackendRegistry: holds multiple backends and routes by hint or capability.
type BackendRegistry interface {
	Lookup(name string) (Backend, error)
	Select(spec CreateKeySpec) (Backend, error)
	List() []Backend
}
