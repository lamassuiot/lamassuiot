package cryptoenginesv2

import (
	"context"
	"crypto"
)

// Asymmetric encryption. alg selects the encryption algorithm (e.g.
// RSAES_OAEP_SHA_256) and must be compatible with the key's KeySpec.
type Encrypter interface {
	KeyHandle
	EncryptContext(ctx context.Context, plaintext []byte, alg AlgorithmID, opts EncryptOpts) ([]byte, error)
}

// Asymmetric decryption. alg selects the encryption algorithm the ciphertext
// was produced with. The embedded crypto.Decrypter.Decrypt is retained for
// stdlib interop and infers the algorithm from opts.
type Decrypter interface {
	KeyHandle
	crypto.Decrypter
	DecryptContext(ctx context.Context, ciphertext []byte, alg AlgorithmID, opts crypto.DecrypterOpts) ([]byte, error)
}

// Symmetric AEAD. alg selects the symmetric algorithm (SYMMETRIC_DEFAULT for
// AES-GCM). Decrypt reads the algorithm from the Ciphertext envelope.
type SymmetricCipher interface {
	KeyHandle
	Encrypt(ctx context.Context, plaintext []byte, alg AlgorithmID, opts SymmetricOpts) (Ciphertext, error)
	Decrypt(ctx context.Context, ct Ciphertext, opts SymmetricOpts) (plaintext []byte, err error)
}
