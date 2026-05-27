package softwarev2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"io"
)

// ecdsaHandle implements cryptoenginesv2.Signer for ECDSA keys.
type ecdsaHandle struct {
	handleBase
}

func (h *ecdsaHandle) Public() crypto.PublicKey { return h.meta.PublicKey }

func (h *ecdsaHandle) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	_ = rand
	return h.signInternal(context.Background(), digest, opts)
}

func (h *ecdsaHandle) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return h.signInternal(ctx, digest, opts)
}

func (h *ecdsaHandle) signInternal(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	_ = opts

	blob, err := h.loadMaterial(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(blob)

	priv, err := decodePrivate(h.meta.Algorithm, blob)
	if err != nil {
		return nil, err
	}
	sk, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("soft: %s did not decode to ECDSA private key", h.meta.Algorithm)
	}

	return ecdsa.SignASN1(randomReader, sk, digest)
}
