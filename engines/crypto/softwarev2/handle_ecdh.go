package softwarev2

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// ecdhHandle implements cryptoenginesv2.KeyAgreementer for X25519 keys.
// (NIST EC keys agree via ecdsaHandle, which owns both signing and agreement.)
type ecdhHandle struct {
	*handleBase
}

func (h *ecdhHandle) privateKey(ctx context.Context) (*ecdh.PrivateKey, error) {
	raw, err := h.loadMaterial(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(raw)

	priv, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("soft: ecdh parse PKCS8: %w", err)
	}
	switch k := priv.(type) {
	case *ecdh.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		// NIST ECDH keys round-trip through PKCS#8 as *ecdsa.PrivateKey
		// because both families share the id-ecPublicKey OID.
		return k.ECDH()
	}
	return nil, fmt.Errorf("soft: expected *ecdh.PrivateKey, got %T", priv)
}

func (h *ecdhHandle) Agree(ctx context.Context, peerPublic crypto.PublicKey, alg cryptoenginesv2.AlgorithmID) ([]byte, error) {
	peer, ok := peerPublic.(*ecdh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("soft: Agree requires *ecdh.PublicKey, got %T", peerPublic)
	}
	sk, err := h.privateKey(ctx)
	if err != nil {
		return nil, err
	}
	return sk.ECDH(peer)
}

func (h *ecdhHandle) AgreeAndDerive(ctx context.Context, peerPublic crypto.PublicKey, alg cryptoenginesv2.AlgorithmID, kdf cryptoenginesv2.KDFParams) ([]byte, error) {
	// Raw ECDH shared secret — KDF application is left for follow-up phases.
	return h.Agree(ctx, peerPublic, alg)
}

// ensure ecdhHandle satisfies the KeyAgreementer interface at compile time.
var _ cryptoenginesv2.KeyAgreementer = (*ecdhHandle)(nil)
