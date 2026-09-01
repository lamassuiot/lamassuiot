package registry

import (
	"crypto"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

type (
	KeySpec       = cryptoenginesv2.KeySpec
	KeySpecInfo   = cryptoenginesv2.KeySpecInfo
	AlgorithmID   = cryptoenginesv2.AlgorithmID
	AlgorithmInfo = cryptoenginesv2.AlgorithmInfo
	Operation     = cryptoenginesv2.Operation
)

const (
	FamilyRSA   = cryptoenginesv2.FamilyRSA
	FamilyECDSA = cryptoenginesv2.FamilyECDSA
	FamilyEdDSA = cryptoenginesv2.FamilyEdDSA
	FamilyECDH  = cryptoenginesv2.FamilyECDH
	FamilyMLKEM = cryptoenginesv2.FamilyMLKEM
	FamilyAES   = cryptoenginesv2.FamilyAES
	FamilyHMAC  = cryptoenginesv2.FamilyHMAC
)

const (
	OpSign        = cryptoenginesv2.OpSign
	OpVerify      = cryptoenginesv2.OpVerify
	OpEncrypt     = cryptoenginesv2.OpEncrypt
	OpDecrypt     = cryptoenginesv2.OpDecrypt
	OpWrapKey     = cryptoenginesv2.OpWrapKey
	OpUnwrapKey   = cryptoenginesv2.OpUnwrapKey
	OpEncapsulate = cryptoenginesv2.OpEncapsulate
	OpDecapsulate = cryptoenginesv2.OpDecapsulate
	OpMAC         = cryptoenginesv2.OpMAC
	OpVerifyMAC   = cryptoenginesv2.OpVerifyMAC
	OpDeriveKey   = cryptoenginesv2.OpDeriveKey
	OpAgreeKey    = cryptoenginesv2.OpAgreeKey
)

// Convenience aliases for the operation sets shared across algorithms.
var (
	opsSignVerify  = []Operation{OpSign, OpVerify}
	opsEncDecWrap  = []Operation{OpEncrypt, OpDecrypt, OpWrapKey, OpUnwrapKey}
	opsEncDec      = []Operation{OpEncrypt, OpDecrypt}
	opsMAC         = []Operation{OpMAC, OpVerifyMAC}
	opsAgree       = []Operation{OpAgreeKey, OpDeriveKey}
	opsKEM         = []Operation{OpEncapsulate, OpDecapsulate, OpWrapKey, OpUnwrapKey}
	rsaKeySpecs    = []KeySpec{cryptoenginesv2.KeySpecRSA2048, cryptoenginesv2.KeySpecRSA3072, cryptoenginesv2.KeySpecRSA4096}
	aesKeySpecs    = []KeySpec{cryptoenginesv2.KeySpecSymmetricDefault, cryptoenginesv2.KeySpecAES128, cryptoenginesv2.KeySpecAES192}
	ecAgreeKeySpec = []KeySpec{
		cryptoenginesv2.KeySpecECCNISTP256, cryptoenginesv2.KeySpecECCNISTP384,
		cryptoenginesv2.KeySpecECCNISTP521, cryptoenginesv2.KeySpecECCSECGP256K1,
		cryptoenginesv2.KeySpecX25519,
	}
)

// NewBuiltinRegistry returns the registry populated with every KeySpec and
// per-operation algorithm supported by this version of the KMS.
func NewBuiltinRegistry() cryptoenginesv2.Registry {
	return NewStaticRegistry(builtinKeySpecs(), builtinAlgorithms())
}

// builtinKeySpecs is the canonical catalog of key material this KMS recognizes.
// Backends advertise their own subset via BackendCapabilities; the Service
// picks a backend able to satisfy the requested KeySpec.
func builtinKeySpecs() []KeySpecInfo {
	var all []KeySpecInfo

	// RSA — one spec per modulus size; each serves signing, OAEP encryption
	// and key wrapping.
	for _, s := range []struct {
		spec KeySpec
		bits int
	}{
		{cryptoenginesv2.KeySpecRSA2048, 2048},
		{cryptoenginesv2.KeySpecRSA3072, 3072},
		{cryptoenginesv2.KeySpecRSA4096, 4096},
	} {
		all = append(all, KeySpecInfo{
			KeySpec:             s.spec,
			Family:              FamilyRSA,
			KeyBits:             s.bits,
			SupportedOperations: []Operation{OpSign, OpVerify, OpEncrypt, OpDecrypt, OpWrapKey, OpUnwrapKey},
			Notes:               "RSA keypair. Serves every RSASSA_* signing algorithm and every RSAES_* encryption algorithm.",
		})
	}

	// Elliptic curve — one EC keypair serves both ECDSA signing and ECDH
	// key agreement.
	for _, s := range []struct {
		spec KeySpec
		bits int
	}{
		{cryptoenginesv2.KeySpecECCNISTP256, 256},
		{cryptoenginesv2.KeySpecECCNISTP384, 384},
		{cryptoenginesv2.KeySpecECCNISTP521, 521},
		{cryptoenginesv2.KeySpecECCSECGP256K1, 256},
	} {
		all = append(all, KeySpecInfo{
			KeySpec:             s.spec,
			Family:              FamilyECDSA,
			KeyBits:             s.bits,
			SupportedOperations: []Operation{OpSign, OpVerify, OpAgreeKey, OpDeriveKey},
			Notes:               "EC keypair. Signs with ECDSA_* and agrees with ECDH from the same key.",
		})
	}

	all = append(all,
		KeySpecInfo{
			KeySpec:             cryptoenginesv2.KeySpecED25519,
			Family:              FamilyEdDSA,
			KeyBits:             255,
			SupportedOperations: opsSignVerify,
			Notes:               "Ed25519 (RFC 8032). Signs the full message; no hash parameter.",
		},
		KeySpecInfo{
			KeySpec:             cryptoenginesv2.KeySpecX25519,
			Family:              FamilyECDH,
			KeyBits:             255,
			SupportedOperations: opsAgree,
			Notes:               "X25519 (RFC 7748). Key agreement only.",
		},
	)

	// Symmetric AEAD.
	for _, s := range []struct {
		spec KeySpec
		bits int
	}{
		{cryptoenginesv2.KeySpecSymmetricDefault, 256},
		{cryptoenginesv2.KeySpecAES128, 128},
		{cryptoenginesv2.KeySpecAES192, 192},
	} {
		all = append(all, KeySpecInfo{
			KeySpec:             s.spec,
			Family:              FamilyAES,
			KeyBits:             s.bits,
			SupportedOperations: opsEncDec,
			Notes:               "AES key. Encrypts with SYMMETRIC_DEFAULT (AES-GCM).",
		})
	}

	// HMAC.
	for _, s := range []struct {
		spec KeySpec
		bits int
	}{
		{cryptoenginesv2.KeySpecHMAC256, 256},
		{cryptoenginesv2.KeySpecHMAC384, 384},
		{cryptoenginesv2.KeySpecHMAC512, 512},
	} {
		all = append(all, KeySpecInfo{
			KeySpec:             s.spec,
			Family:              FamilyHMAC,
			KeyBits:             s.bits,
			SupportedOperations: opsMAC,
			Notes:               "HMAC key (RFC 2104).",
		})
	}

	// ML-KEM (FIPS 203).
	for _, spec := range []KeySpec{cryptoenginesv2.KeySpecMLKEM768, cryptoenginesv2.KeySpecMLKEM1024} {
		all = append(all, KeySpecInfo{
			KeySpec:             spec,
			Family:              FamilyMLKEM,
			SupportedOperations: opsKEM,
			IsPQC:               true,
			Notes:               "ML-KEM (NIST FIPS 203). Encapsulation / key wrapping.",
		})
	}

	return all
}

// builtinAlgorithms is the canonical catalog of per-operation algorithms and
// the KeySpecs each is valid on.
func builtinAlgorithms() []AlgorithmInfo {
	var all []AlgorithmInfo

	// --- RSA signing (any RSA KeySpec) ---
	for _, a := range []struct {
		id     AlgorithmID
		scheme string
		hash   crypto.Hash
	}{
		{cryptoenginesv2.AlgRSASSAPKCS1V15SHA256, "pkcs1v15", crypto.SHA256},
		{cryptoenginesv2.AlgRSASSAPKCS1V15SHA384, "pkcs1v15", crypto.SHA384},
		{cryptoenginesv2.AlgRSASSAPKCS1V15SHA512, "pkcs1v15", crypto.SHA512},
		{cryptoenginesv2.AlgRSASSAPSSSHA256, "pss", crypto.SHA256},
		{cryptoenginesv2.AlgRSASSAPSSSHA384, "pss", crypto.SHA384},
		{cryptoenginesv2.AlgRSASSAPSSSHA512, "pss", crypto.SHA512},
	} {
		all = append(all, AlgorithmInfo{
			ID: a.id, Operations: opsSignVerify, Scheme: a.scheme, Hash: a.hash,
			CompatibleKeySpecs: rsaKeySpecs,
			Notes:              "RSA signature (RFC 8017).",
		})
	}

	// --- RSA encryption / wrapping (any RSA KeySpec) ---
	for _, a := range []struct {
		id   AlgorithmID
		hash crypto.Hash
	}{
		{cryptoenginesv2.AlgRSAESOAEPSHA1, crypto.SHA1},
		{cryptoenginesv2.AlgRSAESOAEPSHA256, crypto.SHA256},
		{cryptoenginesv2.AlgRSAESOAEPSHA384, crypto.SHA384},
		{cryptoenginesv2.AlgRSAESOAEPSHA512, crypto.SHA512},
	} {
		all = append(all, AlgorithmInfo{
			ID: a.id, Operations: opsEncDecWrap, Scheme: "oaep", Hash: a.hash,
			CompatibleKeySpecs: rsaKeySpecs,
			Notes:              "RSAES-OAEP (RFC 8017). Serves Encrypt and WrapKey.",
		})
	}
	all = append(all, AlgorithmInfo{
		ID: cryptoenginesv2.AlgRSAESPKCS1V15, Operations: []Operation{OpDecrypt, OpUnwrapKey},
		Scheme: "pkcs1v15", CompatibleKeySpecs: rsaKeySpecs, Legacy: true,
		Notes: "RSAES-PKCS1-v1_5. Decrypt-only for legacy migration. Never for new encryption.",
	})

	// --- ECDSA (hash paired with curve, AWS convention) ---
	all = append(all,
		AlgorithmInfo{
			ID: cryptoenginesv2.AlgECDSASHA256, Operations: opsSignVerify, Scheme: "ecdsa", Hash: crypto.SHA256,
			CompatibleKeySpecs: []KeySpec{cryptoenginesv2.KeySpecECCNISTP256, cryptoenginesv2.KeySpecECCSECGP256K1},
			Notes:              "ECDSA with SHA-256 (P-256 / secp256k1).",
		},
		AlgorithmInfo{
			ID: cryptoenginesv2.AlgECDSASHA384, Operations: opsSignVerify, Scheme: "ecdsa", Hash: crypto.SHA384,
			CompatibleKeySpecs: []KeySpec{cryptoenginesv2.KeySpecECCNISTP384},
			Notes:              "ECDSA with SHA-384 (P-384).",
		},
		AlgorithmInfo{
			ID: cryptoenginesv2.AlgECDSASHA512, Operations: opsSignVerify, Scheme: "ecdsa", Hash: crypto.SHA512,
			CompatibleKeySpecs: []KeySpec{cryptoenginesv2.KeySpecECCNISTP521},
			Notes:              "ECDSA with SHA-512 (P-521).",
		},
	)

	// --- EdDSA ---
	all = append(all, AlgorithmInfo{
		ID: cryptoenginesv2.AlgED25519, Operations: opsSignVerify, Scheme: "eddsa",
		CompatibleKeySpecs: []KeySpec{cryptoenginesv2.KeySpecED25519},
		Notes:              "Ed25519 (RFC 8032).",
	})

	// --- Symmetric encryption ---
	all = append(all,
		AlgorithmInfo{
			ID: cryptoenginesv2.AlgSymmetricDefault, Operations: opsEncDec, Scheme: "gcm",
			CompatibleKeySpecs: aesKeySpecs,
			Notes:              "AES-GCM (NIST SP 800-38D). 96-bit nonce.",
		},
		AlgorithmInfo{
			ID: cryptoenginesv2.AlgAESCBC, Operations: []Operation{OpDecrypt}, Scheme: "cbc",
			CompatibleKeySpecs: aesKeySpecs, Legacy: true,
			Notes: "AES-CBC. Decrypt-only for legacy migration (not AEAD).",
		},
	)

	// --- MAC (each HMAC algorithm pairs with its HMAC KeySpec) ---
	all = append(all,
		AlgorithmInfo{
			ID: cryptoenginesv2.AlgHMACSHA256, Operations: opsMAC, Scheme: "hmac", Hash: crypto.SHA256,
			CompatibleKeySpecs: []KeySpec{cryptoenginesv2.KeySpecHMAC256}, Notes: "HMAC-SHA-256.",
		},
		AlgorithmInfo{
			ID: cryptoenginesv2.AlgHMACSHA384, Operations: opsMAC, Scheme: "hmac", Hash: crypto.SHA384,
			CompatibleKeySpecs: []KeySpec{cryptoenginesv2.KeySpecHMAC384}, Notes: "HMAC-SHA-384.",
		},
		AlgorithmInfo{
			ID: cryptoenginesv2.AlgHMACSHA512, Operations: opsMAC, Scheme: "hmac", Hash: crypto.SHA512,
			CompatibleKeySpecs: []KeySpec{cryptoenginesv2.KeySpecHMAC512}, Notes: "HMAC-SHA-512.",
		},
	)

	// --- Key agreement ---
	all = append(all, AlgorithmInfo{
		ID: cryptoenginesv2.AlgECDH, Operations: opsAgree, Scheme: "ecdh",
		CompatibleKeySpecs: ecAgreeKeySpec,
		Notes:              "ECDH key agreement; the curve comes from the key.",
	})

	// --- ML-KEM (parameter set fixed by KeySpec) ---
	all = append(all,
		AlgorithmInfo{
			ID: cryptoenginesv2.AlgMLKEM768, Operations: opsKEM, Scheme: "ml-kem",
			CompatibleKeySpecs: []KeySpec{cryptoenginesv2.KeySpecMLKEM768}, Notes: "ML-KEM-768 (FIPS 203).",
		},
		AlgorithmInfo{
			ID: cryptoenginesv2.AlgMLKEM1024, Operations: opsKEM, Scheme: "ml-kem",
			CompatibleKeySpecs: []KeySpec{cryptoenginesv2.KeySpecMLKEM1024}, Notes: "ML-KEM-1024 (FIPS 203).",
		},
	)

	return all
}
