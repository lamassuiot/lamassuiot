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

// Registry is the single source of truth for the two orthogonal concepts of
// the KMS key model:
//
//   - KeySpec  — the key *material* (RSA_2048, ECC_NIST_P256, …). Determines
//     what is generated/stored and which operations the material can perform.
//   - AlgorithmID — a *per-operation* algorithm (scheme + hash, e.g.
//     RSASSA_PSS_SHA_256). Chosen per call and validated against the key's
//     KeySpec and its authorized operations.
//
// A single KeySpec is compatible with many AlgorithmIDs. The Registry answers
// both "what may this KeySpec do" and "is this AlgorithmID valid for this
// KeySpec + operation".
type Registry interface {
	// GetKeySpec returns the material info for spec, or ErrKeySpecNotSupported.
	GetKeySpec(spec KeySpec) (KeySpecInfo, error)

	// ListKeySpecs returns every registered KeySpec info, sorted by spec ID.
	ListKeySpecs() []KeySpecInfo

	// GetAlgorithm returns the per-operation algorithm info for id, or
	// ErrAlgorithmNotSupported.
	GetAlgorithm(id AlgorithmID) (AlgorithmInfo, error)

	// ListAlgorithms returns every registered algorithm, sorted by ID.
	ListAlgorithms() []AlgorithmInfo

	// AlgorithmsFor returns the AlgorithmIDs valid for spec that perform op,
	// sorted by ID. Empty if none.
	AlgorithmsFor(spec KeySpec, op Operation) []AlgorithmID

	// ValidateAlgorithm reports whether alg may perform op on a key of the
	// given KeySpec. It checks that alg performs op and that spec is in alg's
	// compatible KeySpecs. It does NOT check the key's authorized Operations
	// set — that is the Service's responsibility. Returns nil when valid, or
	// ErrAlgorithmNotSupported / ErrOperationNotAllowed otherwise.
	ValidateAlgorithm(spec KeySpec, op Operation, alg AlgorithmID) error
}

// KeySpecInfo is the canonical description of one KeySpec (the key material).
type KeySpecInfo struct {
	// KeySpec is the stable identifier used in API requests and persisted records.
	KeySpec KeySpec

	// Family groups related key material (rsa, ecdsa, ml-kem, ...).
	Family Family

	// KeyBits is the key size in bits when meaningful (RSA modulus, AES key
	// length, EC field size). Zero means N/A (e.g. Ed25519, ML-KEM parameter
	// sets fixed by the spec ID).
	KeyBits int

	// SupportedOperations is the set of operations the material can perform.
	// A CreateKey request may only authorize operations from this set. The
	// actual per-operation algorithm is resolved separately via AlgorithmsFor.
	SupportedOperations []Operation

	// IsPQC is true for NIST post-quantum standards (ML-KEM, ML-DSA, SLH-DSA).
	IsPQC bool

	// Notes is free-form documentation surfaced in diagnostics and OpenAPI.
	Notes string
}

// AlgorithmInfo is the canonical description of one per-operation algorithm.
type AlgorithmInfo struct {
	// ID is the stable identifier used in operation requests (RSASSA_PSS_SHA_256).
	ID AlgorithmID

	// Operations is the set of operations this algorithm performs, including
	// the inverse: a signing algorithm covers {sign, verify}, OAEP covers
	// {encrypt, decrypt, wrapKey, unwrapKey}, ECDH covers {agreeKey, deriveKey}.
	// Callers pass the same AlgorithmID to an operation and its inverse.
	Operations []Operation

	// Scheme is a short mnemonic for the padding/signature scheme
	// ("pkcs1v15", "pss", "oaep", "ecdsa", "eddsa", "gcm", "hmac", "ecdh", ...).
	Scheme string

	// Hash is the hash bound to this algorithm, or crypto.Hash(0) when the
	// hash is fixed by the algorithm (Ed25519, ML-DSA) or not applicable.
	Hash crypto.Hash

	// CompatibleKeySpecs lists the KeySpecs this algorithm may be used with.
	CompatibleKeySpecs []KeySpec

	// Legacy marks consume-only algorithms (decrypt/verify of deprecated
	// schemes). Their Operations list the permitted consume side only.
	Legacy bool

	// Notes is free-form documentation surfaced in diagnostics and OpenAPI.
	Notes string
}

var (
	// ErrAlgorithmNotSupported is returned for unknown/invalid AlgorithmIDs.
	ErrAlgorithmNotSupported = errors.New("algorithm not supported")
	// ErrKeySpecNotSupported is returned by Registry.GetKeySpec for unknown specs.
	ErrKeySpecNotSupported = errors.New("key spec not supported")
)
