// Package legacy exposes a CryptoEngine as a cryptoengines.Backend, so engines written before the Backend
// contract keep working unchanged. It adds no behaviour: every call maps to one CryptoEngine call.
package legacy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/kmip"
)

var (
	// ErrUnsupported is returned for what a CryptoEngine cannot do: keys other than private keys, algorithms
	// other than RSA and ECDSA, and specs that choose the key's identifier (CryptoEngines name their keys).
	ErrUnsupported = errors.New("unknown or unsupported algorithm")
	// ErrInvalidECDSASize is returned for an ECDSA length without a NIST curve.
	ErrInvalidECDSASize = errors.New("invalid ECDSA key size")
	// ErrUnsupportedKeyType is returned when importing a key that is neither RSA nor ECDSA.
	ErrUnsupportedKeyType = errors.New("unsupported private key type")
)

var curves = map[int]elliptic.Curve{
	224: elliptic.P224(),
	256: elliptic.P256(),
	384: elliptic.P384(),
	521: elliptic.P521(),
}

// engineOperations are the operations a CryptoEngine does for each key type and size it supports.
var engineOperations = []kmip.Operation{kmip.OpCreateKeyPair, kmip.OpRegister, kmip.OpSign, kmip.OpDestroy}

type backend struct {
	ce cryptoengines.CryptoEngine
}

// Wrap exposes ce as a Backend.
func Wrap(ce cryptoengines.CryptoEngine) cryptoengines.Backend {
	return &backend{ce: ce}
}

func (b *backend) Capabilities() cryptoengines.Capabilities {
	caps := cryptoengines.Capabilities{}
	for _, kt := range b.ce.GetEngineConfig().SupportedKeyTypes {
		alg, ok := algorithmOf(x509.PublicKeyAlgorithm(kt.Type))
		if !ok {
			continue
		}
		for _, op := range engineOperations {
			caps.Items = append(caps.Items, cryptoengines.Capability{Operation: op, Algorithm: alg, Lengths: kt.Sizes})
		}
	}
	return caps
}

func (b *backend) Generate(ctx context.Context, spec cryptoengines.GenerateSpec) (cryptoengines.KeyHandle, error) {
	if spec.KeyID != "" || spec.ObjectType != kmip.PrivateKey {
		return nil, ErrUnsupported
	}

	var (
		id     string
		signer crypto.Signer
		err    error
	)
	switch spec.Algorithm {
	case kmip.RSA:
		id, signer, err = b.ce.CreateRSAPrivateKey(ctx, spec.Length)
	case kmip.ECDSA:
		curve, ok := curves[spec.Length]
		if !ok {
			return nil, ErrInvalidECDSASize
		}
		id, signer, err = b.ce.CreateECDSAPrivateKey(ctx, curve)
	default:
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, err
	}

	return &signerHandle{
		ref:    cryptoengines.KeyRef{KeyID: id, ObjectType: kmip.PrivateKey, Algorithm: spec.Algorithm, Length: spec.Length},
		Signer: signer,
	}, nil
}

func (b *backend) Import(ctx context.Context, spec cryptoengines.ImportSpec) (cryptoengines.KeyHandle, error) {
	if spec.KeyID != "" || spec.ObjectType != kmip.PrivateKey {
		return nil, ErrUnsupported
	}

	var (
		ref    = cryptoengines.KeyRef{ObjectType: kmip.PrivateKey}
		signer crypto.Signer
		err    error
	)
	switch k := spec.Private.(type) {
	case *rsa.PrivateKey:
		ref.Algorithm, ref.Length = kmip.RSA, k.N.BitLen()
		ref.KeyID, signer, err = b.ce.ImportRSAPrivateKey(ctx, k)
	case *ecdsa.PrivateKey:
		ref.Algorithm, ref.Length = kmip.ECDSA, k.Params().BitSize
		ref.KeyID, signer, err = b.ce.ImportECDSAPrivateKey(ctx, k)
	default:
		return nil, ErrUnsupportedKeyType
	}
	if err != nil {
		return nil, err
	}

	return &signerHandle{ref: ref, Signer: signer}, nil
}

// Load and Destroy only accept private keys: a CryptoEngine names a key pair's private key after the SHA-256 of
// its public key, so a reference to the public half (or anything else) carrying that name must not reach it.

func (b *backend) Load(ctx context.Context, ref cryptoengines.KeyRef) (cryptoengines.KeyHandle, error) {
	if ref.ObjectType != kmip.PrivateKey {
		return nil, ErrUnsupported
	}
	signer, err := b.ce.GetPrivateKeyByID(ctx, ref.KeyID)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, errors.New("engine returned no key")
	}
	return &signerHandle{ref: ref, Signer: signer}, nil
}

func (b *backend) Destroy(ctx context.Context, ref cryptoengines.KeyRef) error {
	if ref.ObjectType != kmip.PrivateKey {
		return ErrUnsupported
	}
	return b.ce.DeleteKey(ctx, ref.KeyID)
}

func algorithmOf(alg x509.PublicKeyAlgorithm) (kmip.CryptographicAlgorithm, bool) {
	switch alg {
	case x509.RSA:
		return kmip.RSA, true
	case x509.ECDSA:
		return kmip.ECDSA, true
	default:
		return 0, false
	}
}
