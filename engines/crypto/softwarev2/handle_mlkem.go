package softwarev2

import (
	"context"
	"crypto"
	"crypto/mlkem"
	"errors"
	"fmt"
)

type mlkemHandle struct {
	handleBase
}

func (h *mlkemHandle) Public() crypto.PublicKey { return h.meta.PublicKey }

// --- crypto.Decapsulator ---

func (h *mlkemHandle) Decapsulate(ciphertext []byte) ([]byte, error) {
	return h.decapsulate(context.Background(), ciphertext)
}

// Encapsulator returns the standard-library public encapsulation key. The
// handle itself does NOT implement crypto.Encapsulator (which requires
// Bytes() on the public key); this method exposes the real public object
// so callers can use it directly with crypto/tls and any consumer of
// crypto.Encapsulator.
func (h *mlkemHandle) Encapsulator() crypto.Encapsulator {
	switch ek := h.meta.PublicKey.(type) {
	case *mlkem.EncapsulationKey768:
		return ek
	case *mlkem.EncapsulationKey1024:
		return ek
	}
	panic(fmt.Sprintf("soft: mlkemHandle has non-ML-KEM public key %T", h.meta.PublicKey))
}

// --- cryptoenginesv2.Decapsulator (context-aware) ---

func (h *mlkemHandle) DecapsulateContext(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return h.decapsulate(ctx, ciphertext)
}

// --- cryptoenginesv2.Encapsulator (context-aware convenience) ---

func (h *mlkemHandle) EncapsulateContext(ctx context.Context) (sharedSecret, ciphertext []byte, err error) {
	if err := h.checkOpen(); err != nil {
		return nil, nil, err
	}
	switch ek := h.meta.PublicKey.(type) {
	case *mlkem.EncapsulationKey768:
		ss, ct := ek.Encapsulate()
		return ss, ct, nil
	case *mlkem.EncapsulationKey1024:
		ss, ct := ek.Encapsulate()
		return ss, ct, nil
	}
	return nil, nil, errors.New("soft: not an ML-KEM key")
}

// --- private ---

func (h *mlkemHandle) decapsulate(ctx context.Context, ct []byte) ([]byte, error) {
	blob, err := h.loadMaterial(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(blob)

	priv, err := decodePrivate(h.meta.Algorithm, blob)
	if err != nil {
		return nil, err
	}
	switch dk := priv.(type) {
	case *mlkem.DecapsulationKey768:
		return dk.Decapsulate(ct)
	case *mlkem.DecapsulationKey1024:
		return dk.Decapsulate(ct)
	}
	return nil, fmt.Errorf("soft: decoded material is not ML-KEM (%T)", priv)
}
