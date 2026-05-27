package registry

import (
	"crypto"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

type (
	AlgorithmID   = cryptoenginesv2.AlgorithmID
	AlgorithmSpec = cryptoenginesv2.AlgorithmSpec
	Operation     = cryptoenginesv2.Operation
)

const (
	FamilyRSA       = cryptoenginesv2.FamilyRSA
	FamilyECDSA     = cryptoenginesv2.FamilyECDSA
	FamilyEdDSA     = cryptoenginesv2.FamilyEdDSA
	FamilyMLDSA     = cryptoenginesv2.FamilyMLDSA
	FamilySLHDSA    = cryptoenginesv2.FamilySLHDSA
	FamilyComposite = cryptoenginesv2.FamilyComposite
	FamilyECDH      = cryptoenginesv2.FamilyECDH
	FamilyMLKEM     = cryptoenginesv2.FamilyMLKEM
	FamilyAES       = cryptoenginesv2.FamilyAES
	FamilyChaCha    = cryptoenginesv2.FamilyChaCha
	FamilyHMAC      = cryptoenginesv2.FamilyHMAC
	FamilyHKDF      = cryptoenginesv2.FamilyHKDF
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

// NewBuiltinRegistry returns the registry populated with every algorithm
// supported by this version of the KMS.
func NewBuiltinRegistry() cryptoenginesv2.Registry {
	return NewStaticRegistry(builtinAlgorithms())
}

// builtinAlgorithms returns the canonical, compiled-in list of algorithms
// supported by this version of the KMS. The list is the single source of
// truth for what the public API will accept; backends advertise their own
// subset via BackendCapabilities, and the Service picks a backend able to
// satisfy the requested spec.
//
// Conventions for this table:
//   - ID strings prefer AWS-style algorithm names where they exist
//     (RSASSA_PSS_SHA_256, ECDSA_SHA_256, HMAC_SHA_256) and uppercase
//     AWS-like identifiers elsewhere.
//   - Composite IDs follow the LAMPS draft pattern but are abbreviated for
//     ergonomics; the precise OID mapping lives in the codec layer.
//   - RequiresStdlib reflects what is achievable with Go 1.24+ crypto/*.
//     ChaCha20-Poly1305 lives in golang.org/x/crypto so it is marked false
//     even though the dependency is "almost stdlib".
func builtinAlgorithms() []AlgorithmSpec {
	var all []AlgorithmSpec
	all = append(all, rsaSignAlgorithms()...)
	all = append(all, rsaEncryptAlgorithms()...)
	all = append(all, ecdsaAlgorithms()...)
	all = append(all, eddsaAlgorithms()...)
	all = append(all, mldsaAlgorithms()...)
	all = append(all, slhdsaAlgorithms()...)
	all = append(all, ecdhKEMAlgorithms()...)
	all = append(all, mlkemAlgorithms()...)
	all = append(all, compositeSignAlgorithms()...)
	all = append(all, compositeKEMAlgorithms()...)
	all = append(all, aesGCMAlgorithms()...)
	all = append(all, aesCBCAlgorithms()...)
	all = append(all, chachaAlgorithms()...)
	all = append(all, hmacAlgorithms()...)
	all = append(all, hkdfAlgorithms()...)
	return all
}

// ---------------------------------------------------------------------------
// RSA signing — PKCS#1 v1.5 and PSS, 2048 / 3072 / 4096
// ---------------------------------------------------------------------------

func rsaSignAlgorithms() []AlgorithmSpec {
	specs := []AlgorithmSpec{}
	for _, size := range []int{2048, 3072, 4096} {
		// PKCS#1 v1.5: kept as a normal-mode algorithm because it remains
		// widely required for X.509 interop. RSA-PSS is preferred for new
		// signatures but PKCS#1 v1.5 is not deprecated for signing per
		// current NIST guidance.
		specs = append(specs, AlgorithmSpec{
			ID:            AlgorithmID(rsaPKCS1Name(size, 256)),
			Family:        FamilyRSA,
			Operations:    []Operation{OpSign, OpVerify},
			AllowedHashes: []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512},
			KeySize:       size,

			Notes: "RSASSA-PKCS1-v1_5 (RFC 8017). Use PSS for new code; this is for X.509 / JWT interop.",
		})
		// RSA-PSS
		specs = append(specs, AlgorithmSpec{
			ID:            AlgorithmID(rsaPSSName(size, 256)),
			Family:        FamilyRSA,
			Operations:    []Operation{OpSign, OpVerify},
			AllowedHashes: []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512},
			KeySize:       size,

			Notes: "RSASSA-PSS (RFC 8017). Preferred over PKCS#1 v1.5 for new code.",
		})
	}
	return specs
}

func rsaPKCS1Name(size, _ int) string {
	switch size {
	case 2048:
		return "RSASSA_PKCS1_V1_5_SHA_256"
	case 3072:
		return "RSASSA_PKCS1_V1_5_SHA_384"
	case 4096:
		return "RSASSA_PKCS1_V1_5_SHA_512"
	}
	return ""
}

func rsaPSSName(size, _ int) string {
	switch size {
	case 2048:
		return "RSASSA_PSS_SHA_256"
	case 3072:
		return "RSASSA_PSS_SHA_384"
	case 4096:
		return "RSASSA_PSS_SHA_512"
	}
	return ""
}

// ---------------------------------------------------------------------------
// RSA asymmetric encryption — OAEP (normal) and PKCS#1 v1.5 (legacy decrypt)
// ---------------------------------------------------------------------------

func rsaEncryptAlgorithms() []AlgorithmSpec {
	specs := []AlgorithmSpec{}

	// RSA-OAEP for each modulus size and each MGF hash.
	for _, size := range []int{2048, 3072, 4096} {
		for _, h := range []struct {
			name string
			hash crypto.Hash
		}{
			{"RSAES_OAEP_SHA_1", crypto.SHA1},
			{"RSAES_OAEP_SHA_256", crypto.SHA256},
			{"RSAES_OAEP_SHA_384", crypto.SHA384},
			{"RSAES_OAEP_SHA_512", crypto.SHA512},
		} {
			specs = append(specs, AlgorithmSpec{
				ID:            AlgorithmID(h.name + "_" + bitLabel(size)),
				Family:        FamilyRSA,
				Operations:    []Operation{OpEncrypt, OpDecrypt, OpWrapKey, OpUnwrapKey},
				AllowedHashes: []crypto.Hash{h.hash},
				KeySize:       size,

				Notes: "RSAES-OAEP (RFC 8017). Same algorithm serves Encrypt and WrapKey; policy distinguishes them.",
			})
		}
	}

	// RSA1_5 — decrypt-only legacy. NOT in Operations, only LegacyOperations.
	// Per our decision: legacy algos are usable only for the consume side.
	for _, size := range []int{2048, 3072, 4096} {
		specs = append(specs, AlgorithmSpec{
			ID:               AlgorithmID("RSAES_PKCS1_V1_5_" + bitLabel(size)),
			Family:           FamilyRSA,
			Operations:       nil, // intentionally empty in normal mode
			LegacyOperations: []Operation{OpDecrypt, OpUnwrapKey},
			KeySize:          size,

			Notes: "RSAES-PKCS1-v1_5. Decrypt-only for migration of legacy ciphertexts. NEVER use for new encryption.",
		})
	}

	return specs
}

// ---------------------------------------------------------------------------
// ECDSA — NIST P-curves and secp256k1
// ---------------------------------------------------------------------------

func ecdsaAlgorithms() []AlgorithmSpec {
	return []AlgorithmSpec{
		{
			ID:            "ECDSA_SHA_256",
			Family:        FamilyECDSA,
			Operations:    []Operation{OpSign, OpVerify},
			AllowedHashes: []crypto.Hash{crypto.SHA256},
			KeySize:       256,

			Notes: "ECDSA over NIST P-256 with SHA-256.",
		},
		{
			ID:            "ECDSA_SHA_384",
			Family:        FamilyECDSA,
			Operations:    []Operation{OpSign, OpVerify},
			AllowedHashes: []crypto.Hash{crypto.SHA384},
			KeySize:       384,

			Notes: "ECDSA over NIST P-384 with SHA-384.",
		},
		{
			ID:            "ECDSA_SHA_512",
			Family:        FamilyECDSA,
			Operations:    []Operation{OpSign, OpVerify},
			AllowedHashes: []crypto.Hash{crypto.SHA512},
			KeySize:       521,

			Notes: "ECDSA over NIST P-521 with SHA-512.",
		},
		{
			ID:            "ECDSA_SHA_256_ECC_SECG_P256K1",
			Family:        FamilyECDSA,
			Operations:    []Operation{OpSign, OpVerify},
			AllowedHashes: []crypto.Hash{crypto.SHA256},
			KeySize:       256,
			// secp256k1 not in stdlib
			Notes: "ECDSA over secp256k1 with SHA-256. Requires external dependency (dcrec or btcec).",
		},
	}
}

// ---------------------------------------------------------------------------
// EdDSA
// ---------------------------------------------------------------------------

func eddsaAlgorithms() []AlgorithmSpec {
	return []AlgorithmSpec{
		{
			ID:            "ED25519",
			Family:        FamilyEdDSA,
			Operations:    []Operation{OpSign, OpVerify},
			AllowedHashes: nil, // signs the message, not a pre-hash
			KeySize:       255,

			Notes: "Ed25519 (RFC 8032). Signs the full message; the hash parameter is ignored.",
		},
	}
}

// ---------------------------------------------------------------------------
// ML-DSA (FIPS 204)
// ---------------------------------------------------------------------------

func mldsaAlgorithms() []AlgorithmSpec {
	return []AlgorithmSpec{
		{
			ID:         "ML_DSA_44",
			Family:     FamilyMLDSA,
			Operations: []Operation{OpSign, OpVerify},
			IsPQC:      true,
			// CIRCL
			Notes: "ML-DSA-44 (NIST FIPS 204), security category 2. Pure mode: signs message directly.",
		},
		{
			ID:         "ML_DSA_65",
			Family:     FamilyMLDSA,
			Operations: []Operation{OpSign, OpVerify},
			IsPQC:      true,

			Notes: "ML-DSA-65 (NIST FIPS 204), security category 3. Recommended default.",
		},
		{
			ID:         "ML_DSA_87",
			Family:     FamilyMLDSA,
			Operations: []Operation{OpSign, OpVerify},
			IsPQC:      true,

			Notes: "ML-DSA-87 (NIST FIPS 204), security category 5.",
		},
	}
}

// ---------------------------------------------------------------------------
// SLH-DSA (FIPS 205)
// ---------------------------------------------------------------------------

func slhdsaAlgorithms() []AlgorithmSpec {
	return []AlgorithmSpec{
		{
			ID:         "SLH_DSA_SHA2_128S",
			Family:     FamilySLHDSA,
			Operations: []Operation{OpSign, OpVerify},
			IsPQC:      true,

			Notes: "SLH-DSA-SHA2-128s (NIST FIPS 205). Stateless hash-based. Slow signing, small keys, very long-term security.",
		},
		{
			ID:         "SLH_DSA_SHA2_192S",
			Family:     FamilySLHDSA,
			Operations: []Operation{OpSign, OpVerify},
			IsPQC:      true,

			Notes: "SLH-DSA-SHA2-192s (NIST FIPS 205). Use for firmware signing requiring decades of security.",
		},
	}
}

// ---------------------------------------------------------------------------
// ECDH (key agreement) treated as KEM in this API
// ---------------------------------------------------------------------------

func ecdhKEMAlgorithms() []AlgorithmSpec {
	return []AlgorithmSpec{
		{
			ID:         "ECDH_NIST_P256",
			Family:     FamilyECDH,
			Operations: []Operation{OpAgreeKey, OpEncapsulate, OpDecapsulate, OpDeriveKey},
			KeySize:    256,

			Notes: "ECDH over NIST P-256. Used standalone or as classical half of composite KEM.",
		},
		{
			ID:         "ECDH_NIST_P384",
			Family:     FamilyECDH,
			Operations: []Operation{OpAgreeKey, OpEncapsulate, OpDecapsulate, OpDeriveKey},
			KeySize:    384,

			Notes: "ECDH over NIST P-384.",
		},
		{
			ID:         "ECDH_NIST_P521",
			Family:     FamilyECDH,
			Operations: []Operation{OpAgreeKey, OpEncapsulate, OpDecapsulate, OpDeriveKey},
			KeySize:    521,

			Notes: "ECDH over NIST P-521.",
		},
		{
			ID:         "ECDH_X25519",
			Family:     FamilyECDH,
			Operations: []Operation{OpAgreeKey, OpEncapsulate, OpDecapsulate, OpDeriveKey},
			KeySize:    255,

			Notes: "X25519 (RFC 7748). Preferred classical KEX for performance.",
		},
	}
}

// ---------------------------------------------------------------------------
// ML-KEM (FIPS 203)
// ---------------------------------------------------------------------------

func mlkemAlgorithms() []AlgorithmSpec {
	return []AlgorithmSpec{
		{
			ID:         "ML_KEM_512",
			Family:     FamilyMLKEM,
			Operations: []Operation{OpEncapsulate, OpDecapsulate, OpWrapKey, OpUnwrapKey},
			IsPQC:      true,
			// stdlib only ships 768/1024; 512 via CIRCL
			Notes: "ML-KEM-512 (NIST FIPS 203), security category 1. CIRCL only — stdlib does not ship 512.",
		},
		{
			ID:         "ML_KEM_768",
			Family:     FamilyMLKEM,
			Operations: []Operation{OpEncapsulate, OpDecapsulate, OpWrapKey, OpUnwrapKey},
			IsPQC:      true,

			Notes: "ML-KEM-768 (NIST FIPS 203), security category 3. Recommended default. crypto/mlkem (Go 1.24+).",
		},
		{
			ID:         "ML_KEM_1024",
			Family:     FamilyMLKEM,
			Operations: []Operation{OpEncapsulate, OpDecapsulate, OpWrapKey, OpUnwrapKey},
			IsPQC:      true,

			Notes: "ML-KEM-1024 (NIST FIPS 203), security category 5. crypto/mlkem (Go 1.24+).",
		},
	}
}

// ---------------------------------------------------------------------------
// Composite signatures (LAMPS draft)
// ---------------------------------------------------------------------------

func compositeSignAlgorithms() []AlgorithmSpec {
	return []AlgorithmSpec{
		{
			ID:                  "COMPOSITE_ML_DSA_44_ED25519",
			Family:              FamilyComposite,
			Operations:          []Operation{OpSign, OpVerify},
			IsPQC:               true,
			IsComposite:         true,
			CompositeComponents: []AlgorithmID{"ML_DSA_44", "ED25519"},
			Notes:               "Composite signature: ML-DSA-44 + Ed25519. Mapped to id-MLDSA44-Ed25519 (LAMPS draft).",
		},
		{
			ID:                  "COMPOSITE_ML_DSA_65_ECDSA_P256",
			Family:              FamilyComposite,
			Operations:          []Operation{OpSign, OpVerify},
			AllowedHashes:       []crypto.Hash{crypto.SHA256},
			IsPQC:               true,
			IsComposite:         true,
			CompositeComponents: []AlgorithmID{"ML_DSA_65", "ECDSA_SHA_256"},
			Notes:               "Composite signature: ML-DSA-65 + ECDSA-P256-SHA256.",
		},
		{
			ID:                  "COMPOSITE_ML_DSA_65_RSA3072_PSS",
			Family:              FamilyComposite,
			Operations:          []Operation{OpSign, OpVerify},
			AllowedHashes:       []crypto.Hash{crypto.SHA256},
			IsPQC:               true,
			IsComposite:         true,
			CompositeComponents: []AlgorithmID{"ML_DSA_65", "RSASSA_PSS_SHA_384"},
			Notes:               "Composite signature: ML-DSA-65 + RSA-3072-PSS-SHA256.",
		},
		{
			ID:                  "COMPOSITE_ML_DSA_87_ECDSA_P384",
			Family:              FamilyComposite,
			Operations:          []Operation{OpSign, OpVerify},
			AllowedHashes:       []crypto.Hash{crypto.SHA384},
			IsPQC:               true,
			IsComposite:         true,
			CompositeComponents: []AlgorithmID{"ML_DSA_87", "ECDSA_SHA_384"},
			Notes:               "Composite signature: ML-DSA-87 + ECDSA-P384-SHA384.",
		},
		{
			ID:                  "COMPOSITE_SLH_DSA_128S_ED25519",
			Family:              FamilyComposite,
			Operations:          []Operation{OpSign, OpVerify},
			IsPQC:               true,
			IsComposite:         true,
			CompositeComponents: []AlgorithmID{"SLH_DSA_SHA2_128S", "ED25519"},
			Notes:               "Composite signature: SLH-DSA-128s + Ed25519. For very long-term firmware signing.",
		},
	}
}

// ---------------------------------------------------------------------------
// Composite KEM (LAMPS draft)
// ---------------------------------------------------------------------------

func compositeKEMAlgorithms() []AlgorithmSpec {
	return []AlgorithmSpec{
		{
			ID:                  "COMPOSITE_ML_KEM_768_ECDH_P256",
			Family:              FamilyComposite,
			Operations:          []Operation{OpEncapsulate, OpDecapsulate, OpWrapKey, OpUnwrapKey},
			IsPQC:               true,
			IsComposite:         true,
			CompositeComponents: []AlgorithmID{"ML_KEM_768", "ECDH_NIST_P256"},
			Notes:               "Composite KEM: ML-KEM-768 + ECDH-P256.",
		},
		{
			ID:                  "COMPOSITE_ML_KEM_768_X25519",
			Family:              FamilyComposite,
			Operations:          []Operation{OpEncapsulate, OpDecapsulate, OpWrapKey, OpUnwrapKey},
			IsPQC:               true,
			IsComposite:         true,
			CompositeComponents: []AlgorithmID{"ML_KEM_768", "ECDH_X25519"},
			Notes:               "Composite KEM: ML-KEM-768 + X25519. Matches Go 1.24 TLS X25519MLKEM768.",
		},
		{
			ID:                  "COMPOSITE_ML_KEM_1024_ECDH_P384",
			Family:              FamilyComposite,
			Operations:          []Operation{OpEncapsulate, OpDecapsulate, OpWrapKey, OpUnwrapKey},
			IsPQC:               true,
			IsComposite:         true,
			CompositeComponents: []AlgorithmID{"ML_KEM_1024", "ECDH_NIST_P384"},
			Notes:               "Composite KEM: ML-KEM-1024 + ECDH-P384. Highest classical+PQC strength.",
		},
	}
}

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------

func aesGCMAlgorithms() []AlgorithmSpec {
	specs := []AlgorithmSpec{}
	for _, bits := range []int{128, 192, 256} {
		specs = append(specs, AlgorithmSpec{
			ID:         AlgorithmID("AES_GCM_" + bitLabel(bits)),
			Family:     FamilyAES,
			Operations: []Operation{OpEncrypt, OpDecrypt},
			KeySize:    bits,

			Notes: "AES-GCM (NIST SP 800-38D). 96-bit nonce required.",
		})
	}
	return specs
}

// ---------------------------------------------------------------------------
// AES-CBC — DECRYPT ONLY (legacy)
// ---------------------------------------------------------------------------

func aesCBCAlgorithms() []AlgorithmSpec {
	specs := []AlgorithmSpec{}
	for _, bits := range []int{128, 192, 256} {
		specs = append(specs, AlgorithmSpec{
			ID:               AlgorithmID("AES_CBC_" + bitLabel(bits)),
			Family:           FamilyAES,
			Operations:       nil, // legacy only
			LegacyOperations: []Operation{OpDecrypt},
			KeySize:          bits,

			Notes: "AES-CBC with PKCS#7 padding. Decrypt-only for migration. NEVER use for new encryption (not AEAD).",
		})
	}
	return specs
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305
// ---------------------------------------------------------------------------

func chachaAlgorithms() []AlgorithmSpec {
	return []AlgorithmSpec{
		{
			ID:         "CHACHA20_POLY1305",
			Family:     FamilyChaCha,
			Operations: []Operation{OpEncrypt, OpDecrypt},
			KeySize:    256,
			// golang.org/x/crypto/chacha20poly1305
			Notes: "ChaCha20-Poly1305 (RFC 8439). Useful for clients without AES hardware acceleration.",
		},
	}
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

func hmacAlgorithms() []AlgorithmSpec {
	return []AlgorithmSpec{
		{
			ID:            "HMAC_SHA_256",
			Family:        FamilyHMAC,
			Operations:    []Operation{OpMAC, OpVerifyMAC},
			AllowedHashes: []crypto.Hash{crypto.SHA256},
			KeySize:       256,

			Notes: "HMAC-SHA-256 (RFC 2104). Recommended key length 32 bytes.",
		},
		{
			ID:            "HMAC_SHA_384",
			Family:        FamilyHMAC,
			Operations:    []Operation{OpMAC, OpVerifyMAC},
			AllowedHashes: []crypto.Hash{crypto.SHA384},
			KeySize:       384,

			Notes: "HMAC-SHA-384.",
		},
		{
			ID:            "HMAC_SHA_512",
			Family:        FamilyHMAC,
			Operations:    []Operation{OpMAC, OpVerifyMAC},
			AllowedHashes: []crypto.Hash{crypto.SHA512},
			KeySize:       512,

			Notes: "HMAC-SHA-512.",
		},
	}
}

// ---------------------------------------------------------------------------
// HKDF
// ---------------------------------------------------------------------------

func hkdfAlgorithms() []AlgorithmSpec {
	return []AlgorithmSpec{
		{
			ID:            "HKDF_SHA_256",
			Family:        FamilyHKDF,
			Operations:    []Operation{OpDeriveKey},
			AllowedHashes: []crypto.Hash{crypto.SHA256},

			Notes: "HKDF-Extract+Expand with SHA-256 (RFC 5869). crypto/hkdf (Go 1.24+).",
		},
		{
			ID:            "HKDF_SHA_384",
			Family:        FamilyHKDF,
			Operations:    []Operation{OpDeriveKey},
			AllowedHashes: []crypto.Hash{crypto.SHA384},

			Notes: "HKDF with SHA-384.",
		},
		{
			ID:            "HKDF_SHA_512",
			Family:        FamilyHKDF,
			Operations:    []Operation{OpDeriveKey},
			AllowedHashes: []crypto.Hash{crypto.SHA512},

			Notes: "HKDF with SHA-512.",
		},
	}
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func bitLabel(bits int) string {
	switch bits {
	case 128:
		return "128"
	case 192:
		return "192"
	case 256:
		return "256"
	case 384:
		return "384"
	case 512:
		return "512"
	case 521:
		return "521"
	case 2048:
		return "2048"
	case 3072:
		return "3072"
	case 4096:
		return "4096"
	}
	return ""
}
