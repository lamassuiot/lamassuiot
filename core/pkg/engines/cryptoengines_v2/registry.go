package cryptoenginesv2

import (
	"crypto"
	"errors"
)

type Family string

const (
	FamilyRSA       Family = "rsa"
	FamilyECDSA     Family = "ecdsa"
	FamilyEdDSA     Family = "eddsa"
	FamilyMLDSA     Family = "ml-dsa"
	FamilySLHDSA    Family = "slh-dsa"
	FamilyComposite Family = "composite"
	FamilyECDH      Family = "ecdh"
	FamilyMLKEM     Family = "ml-kem"
	FamilyRSAKEM    Family = "rsa-kem"
	FamilyAES       Family = "aes"
	FamilyChaCha    Family = "chacha20-poly1305"
	FamilyHMAC      Family = "hmac"
	FamilyHKDF      Family = "hkdf"
	FamilyAESKW     Family = "aes-kw"
)

// Registry resolves AlgorithmID -> AlgorithmSpec and answers capability
// queries. It is the single source of truth for what each algorithm is
// allowed to do (operations) and how it must be parameterized (hashes,
// key sizes, composite components).
type Registry interface {
	// Get returns the spec for id, or ErrAlgorithmNotSupported.
	Get(id AlgorithmID) (AlgorithmSpec, error)

	// List returns every registered algorithm, sorted by ID for stable
	// output (useful for diagnostics endpoints and tests).
	List() []AlgorithmSpec

	// SupportsOperation reports whether id permits op in normal mode.
	SupportsOperation(id AlgorithmID, op Operation) bool

	// SupportsLegacyOperation reports whether id permits op in legacy mode.
	// Legacy operations are a superset of, but never override, normal ones:
	// a caller asking to perform op must satisfy at least one of them.
	SupportsLegacyOperation(id AlgorithmID, op Operation) bool
}

// AlgorithmSpec is the canonical description of one algorithm. Every field
// is documented because this struct is the contract between the registry
// and the rest of the system (Service validation, Backend capability
// negotiation, policy evaluation, audit metadata).
type AlgorithmSpec struct {
	// ID is the stable identifier used in API requests and persisted records.
	ID AlgorithmID

	// Family groups related algorithms (rsa, ecdsa, ml-kem, ...).
	Family Family

	// Operations the algorithm may perform in normal mode. A request asking
	// for an operation not in this set (and not in LegacyOperations) MUST be
	// rejected by the Service before reaching the Backend.
	Operations []Operation

	// LegacyOperations are additionally allowed only for the "consume" side
	// of deprecated algorithms (decrypt-only, verify-only) so existing data
	// remains accessible. They never grant the producing side (no encrypt,
	// no sign) for deprecated algorithms.
	LegacyOperations []Operation

	// AllowedHashes lists hashes the algorithm accepts as a parameter.
	// Empty means: the hash is fixed by the algorithm (Ed25519, ML-DSA) or
	// not applicable (AES-KW, ChaCha20-Poly1305).
	AllowedHashes []crypto.Hash

	// KeySize is the key size in bits, when meaningful. For RSA it's the
	// modulus size; for AES the key length; for ML-* and SLH-* it's the
	// parameter-set-equivalent strength (informational only — the parameter
	// set is fixed by ID). Zero means N/A.
	KeySize int

	// IsPQC is true for NIST post-quantum standards (ML-KEM, ML-DSA, SLH-DSA)
	// and for composite algorithms whose PQC component is one of these.
	IsPQC bool

	// IsComposite is true for hybrid classical+PQC algorithms. When true,
	// CompositeComponents lists the component algorithm IDs in canonical
	// order (PQC first, then classical, per the LAMPS draft convention).
	IsComposite         bool
	CompositeComponents []AlgorithmID

	// Notes is free-form documentation surfaced in diagnostics and OpenAPI.
	Notes string
}

// ErrAlgorithmNotSupported is returned by Registry.Get for unknown IDs.
var ErrAlgorithmNotSupported = errors.New("algorithm not supported")
