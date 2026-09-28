package cryptoenginesv2

type KeyHandle interface {
	Metadata() KeyMetadata
	BackendURI() string // opaque locator within the owning backend
	Close() error
}
