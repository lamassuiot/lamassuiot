package softwarev2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// aesHandle implements cryptoenginesv2.SymmetricCipher for AES-GCM keys.
type aesHandle struct {
	handleBase
}

func (h *aesHandle) Encrypt(ctx context.Context, plaintext []byte, opts cryptoenginesv2.SymmetricOpts) (cryptoenginesv2.Ciphertext, error) {
	if h.meta.Algorithm != "AES_GCM_128" && h.meta.Algorithm != "AES_GCM_192" && h.meta.Algorithm != "AES_GCM_256" {
		return cryptoenginesv2.Ciphertext{}, fmt.Errorf("soft: %s does not support symmetric encrypt", h.meta.Algorithm)
	}

	keyMaterial, err := h.loadMaterial(ctx)
	if err != nil {
		return cryptoenginesv2.Ciphertext{}, err
	}
	defer zero(keyMaterial)

	block, err := aes.NewCipher(keyMaterial)
	if err != nil {
		return cryptoenginesv2.Ciphertext{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return cryptoenginesv2.Ciphertext{}, err
	}

	nonce := opts.Nonce
	if len(nonce) == 0 {
		nonce = make([]byte, aead.NonceSize())
		if _, err := randomReader.Read(nonce); err != nil {
			return cryptoenginesv2.Ciphertext{}, err
		}
	} else if len(nonce) != aead.NonceSize() {
		return cryptoenginesv2.Ciphertext{}, fmt.Errorf("soft: AES-GCM nonce must be %d bytes", aead.NonceSize())
	}

	ct := aead.Seal(nil, nonce, plaintext, opts.AssociatedData)
	return cryptoenginesv2.Ciphertext{
		Algorithm: h.meta.Algorithm,
		Nonce:     append([]byte(nil), nonce...),
		Bytes:     ct,
		AAD:       append([]byte(nil), opts.AssociatedData...),
	}, nil
}

func (h *aesHandle) Decrypt(ctx context.Context, ct cryptoenginesv2.Ciphertext, opts cryptoenginesv2.SymmetricOpts) ([]byte, error) {
	if h.meta.Algorithm != "AES_GCM_128" && h.meta.Algorithm != "AES_GCM_192" && h.meta.Algorithm != "AES_GCM_256" {
		return nil, fmt.Errorf("soft: %s does not support symmetric decrypt", h.meta.Algorithm)
	}

	keyMaterial, err := h.loadMaterial(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(keyMaterial)

	block, err := aes.NewCipher(keyMaterial)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := ct.Nonce
	if len(opts.Nonce) != 0 {
		nonce = opts.Nonce
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("soft: AES-GCM nonce must be %d bytes", aead.NonceSize())
	}

	aad := ct.AAD
	if len(opts.AssociatedData) != 0 {
		aad = opts.AssociatedData
	}

	return aead.Open(nil, nonce, ct.Bytes, aad)
}
