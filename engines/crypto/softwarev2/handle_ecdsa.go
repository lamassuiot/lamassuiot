package softwarev2

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"fmt"
	"io"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// ecdsaHandle implements cryptoenginesv2.Signer AND cryptoenginesv2.KeyAgreementer
// for EC keys: one EC keypair signs with ECDSA and agrees with ECDH.
type ecdsaHandle struct {
	*handleBase
}

func (h *ecdsaHandle) Public() crypto.PublicKey { return h.meta.PublicKey }

func (h *ecdsaHandle) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	_ = rand
	return h.signInternal(context.Background(), digest)
}

func (h *ecdsaHandle) SignContext(ctx context.Context, digest []byte, alg cryptoenginesv2.AlgorithmID, opts crypto.SignerOpts) ([]byte, error) {
	// The hash is already applied to digest; alg selects the ECDSA variant
	// (curve pairing) which is enforced at validation time against the KeySpec.
	return h.signInternal(ctx, digest)
}

func (h *ecdsaHandle) signInternal(ctx context.Context, digest []byte) ([]byte, error) {
	sk, err := h.privateKey(ctx)
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(randomReader, sk, digest)
}

// privateKey loads and decodes the EC private key.
func (h *ecdsaHandle) privateKey(ctx context.Context) (*ecdsa.PrivateKey, error) {
	blob, err := h.loadMaterial(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(blob)

	priv, err := decodePrivate(h.meta.KeySpec, blob)
	if err != nil {
		return nil, err
	}
	sk, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("soft: %s did not decode to ECDSA private key", h.meta.KeySpec)
	}
	return sk, nil
}

// --- cryptoenginesv2.KeyAgreementer (ECDH from the same EC key) ---

func (h *ecdsaHandle) Agree(ctx context.Context, peerPublic crypto.PublicKey, alg cryptoenginesv2.AlgorithmID) ([]byte, error) {
	peer, ok := peerPublic.(*ecdh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("soft: Agree requires *ecdh.PublicKey, got %T", peerPublic)
	}
	sk, err := h.privateKey(ctx)
	if err != nil {
		return nil, err
	}
	ecdhKey, err := sk.ECDH()
	if err != nil {
		return nil, fmt.Errorf("soft: EC key does not support ECDH: %w", err)
	}
	return ecdhKey.ECDH(peer)
}

func (h *ecdsaHandle) AgreeAndDerive(ctx context.Context, peerPublic crypto.PublicKey, alg cryptoenginesv2.AlgorithmID, kdf cryptoenginesv2.KDFParams) ([]byte, error) {
	// Raw ECDH shared secret — KDF application is left for follow-up phases.
	return h.Agree(ctx, peerPublic, alg)
}

var (
	_ cryptoenginesv2.Signer         = (*ecdsaHandle)(nil)
	_ cryptoenginesv2.KeyAgreementer = (*ecdsaHandle)(nil)
)
