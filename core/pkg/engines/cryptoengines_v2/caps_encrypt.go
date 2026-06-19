package cryptoenginesv2

import (
	"context"
	"crypto"
)

// Asymmetric encryption
type Encrypter interface {
	KeyHandle
	EncryptContext(ctx context.Context, plaintext []byte, opts EncryptOpts) ([]byte, error)
}

// Asymmetric decryption
type Decrypter interface {
	KeyHandle
	crypto.Decrypter
	DecryptContext(ctx context.Context, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error)
}

// Symmetric AEAD
type SymmetricCipher interface {
	KeyHandle
	Encrypt(ctx context.Context, plaintext []byte, opts SymmetricOpts) (Ciphertext, error)
	Decrypt(ctx context.Context, ct Ciphertext, opts SymmetricOpts) (plaintext []byte, err error)
}
