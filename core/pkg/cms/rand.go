package cms

import "crypto/rand"

// randReader is the source of cryptographic randomness for signing and CEK/IV
// generation. It is a package variable so tests can substitute a deterministic
// reader if needed; production code uses crypto/rand.
var randReader = rand.Reader

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := randReader.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
