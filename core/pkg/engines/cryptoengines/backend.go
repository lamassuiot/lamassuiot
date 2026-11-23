package cryptoengines

import (
	"context"
	"crypto"
	"slices"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/kmip"
)

// KeyRef points at one key in one backend. KeyID is the KMS identifier of the key (its KMIP Unique
// Identifier); the backend finds the key's bytes with it.
type KeyRef struct {
	KeyID      string
	ObjectType kmip.ObjectType
	Algorithm  kmip.CryptographicAlgorithm
	Length     int // RSA modulus bits, EC curve bits, AES key bits
}

// GenerateSpec describes a key to generate.
type GenerateSpec struct {
	ObjectType kmip.ObjectType // PrivateKey: the private half of a key pair
	Algorithm  kmip.CryptographicAlgorithm
	Length     int
	// KeyID is the identifier to give the key. Empty: the backend names it and returns the name in the
	// handle's Ref() (asymmetric keys: the SHA-256 of the public key).
	KeyID string
}

// ImportSpec describes a key to import.
type ImportSpec struct {
	ObjectType kmip.ObjectType
	KeyID      string            // same rule as GenerateSpec.KeyID
	Private    crypto.PrivateKey // *rsa.PrivateKey or *ecdsa.PrivateKey
}

// Capability is one operation a backend can do with keys of an algorithm and one of the listed lengths.
type Capability struct {
	Operation kmip.Operation
	Algorithm kmip.CryptographicAlgorithm
	Lengths   []int
}

// Capabilities lists what a backend can do.
type Capabilities struct {
	Items []Capability
}

// Supports reports whether the backend can do op with a key of algorithm alg and the given length.
func (c Capabilities) Supports(op kmip.Operation, alg kmip.CryptographicAlgorithm, length int) bool {
	for _, item := range c.Items {
		if item.Operation == op && item.Algorithm == alg && slices.Contains(item.Lengths, length) {
			return true
		}
	}
	return false
}

// Backend is the contract between the KMS and a place that holds keys. What can be done with a loaded key is
// found by asserting its handle to a capability interface, such as Signer.
type Backend interface {
	Capabilities() Capabilities
	Generate(ctx context.Context, spec GenerateSpec) (KeyHandle, error)
	Import(ctx context.Context, spec ImportSpec) (KeyHandle, error)
	Load(ctx context.Context, ref KeyRef) (KeyHandle, error)
	Destroy(ctx context.Context, ref KeyRef) error
}
