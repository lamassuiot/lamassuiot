package keystorager

type KeyStorager interface {
	Get(keyID string) ([]byte, error)
	Create(keyID string, key []byte) error
	Delete(keyID string) error
}
