package keystore

type KeyStore interface {
	Get(keyID string) ([]byte, error)
	Create(keyID string, key []byte) error
	Delete(keyID string) error
}
