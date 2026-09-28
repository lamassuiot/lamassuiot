package cryptoenginesv2

// Typed constants for every per-operation AlgorithmID understood by this
// version of the KMS. Use these instead of raw strings throughout the codebase.
//
// An AlgorithmID identifies a *per-operation* algorithm (scheme + hash), NOT
// the key material — that is the KeySpec (see key_specs.go). A single KeySpec
// (e.g. RSA_2048) is compatible with many AlgorithmIDs, and the caller chooses
// one per operation. The registry (registry.go) records, for each AlgorithmID,
// which operations it performs and which KeySpecs it is valid on.
//
// Following AWS KMS, algorithm IDs do NOT encode the key size: RSAES_OAEP_SHA_256
// is valid on RSA_2048/3072/4096 alike, with the modulus coming from the key.
const (
	// --- Signing (SigningAlgorithm) ---

	// RSA signing — PKCS#1 v1.5. Valid on any RSA KeySpec.
	AlgRSASSAPKCS1V15SHA256 AlgorithmID = "RSASSA_PKCS1_V1_5_SHA_256"
	AlgRSASSAPKCS1V15SHA384 AlgorithmID = "RSASSA_PKCS1_V1_5_SHA_384"
	AlgRSASSAPKCS1V15SHA512 AlgorithmID = "RSASSA_PKCS1_V1_5_SHA_512"

	// RSA signing — PSS. Valid on any RSA KeySpec.
	AlgRSASSAPSSSHA256 AlgorithmID = "RSASSA_PSS_SHA_256"
	AlgRSASSAPSSSHA384 AlgorithmID = "RSASSA_PSS_SHA_384"
	AlgRSASSAPSSSHA512 AlgorithmID = "RSASSA_PSS_SHA_512"

	// ECDSA. Each hash pairs with the matching NIST curve (AWS convention);
	// SHA-256 additionally serves secp256k1.
	AlgECDSASHA256 AlgorithmID = "ECDSA_SHA_256"
	AlgECDSASHA384 AlgorithmID = "ECDSA_SHA_384"
	AlgECDSASHA512 AlgorithmID = "ECDSA_SHA_512"

	// EdDSA — hash fixed by the algorithm.
	AlgED25519 AlgorithmID = "ED25519"

	// --- Asymmetric encryption / wrapping (EncryptionAlgorithm) ---

	// RSA-OAEP — size-independent, valid on any RSA KeySpec.
	AlgRSAESOAEPSHA1   AlgorithmID = "RSAES_OAEP_SHA_1"
	AlgRSAESOAEPSHA256 AlgorithmID = "RSAES_OAEP_SHA_256"
	AlgRSAESOAEPSHA384 AlgorithmID = "RSAES_OAEP_SHA_384"
	AlgRSAESOAEPSHA512 AlgorithmID = "RSAES_OAEP_SHA_512"

	// RSA PKCS#1 v1.5 encryption — legacy decrypt only.
	AlgRSAESPKCS1V15 AlgorithmID = "RSAES_PKCS1_V1_5"

	// --- Symmetric encryption (EncryptionAlgorithm) ---

	// SYMMETRIC_DEFAULT selects the symmetric key's native AEAD (AES-GCM for
	// AES KeySpecs), following AWS KMS.
	AlgSymmetricDefault AlgorithmID = "SYMMETRIC_DEFAULT"

	// AES-CBC — legacy decrypt only.
	AlgAESCBC AlgorithmID = "AES_CBC"

	// --- MAC (MacAlgorithm) ---

	AlgHMACSHA256 AlgorithmID = "HMAC_SHA_256"
	AlgHMACSHA384 AlgorithmID = "HMAC_SHA_384"
	AlgHMACSHA512 AlgorithmID = "HMAC_SHA_512"

	// --- Key agreement (KeyAgreementAlgorithm) ---

	// ECDH — valid on any EC or X25519 KeySpec; the curve comes from the key.
	AlgECDH AlgorithmID = "ECDH"

	// --- KEM (extension beyond AWS KMS) ---

	// ML-KEM encapsulation — the parameter set is fixed by the KeySpec, so the
	// algorithm ID mirrors the spec name.
	AlgMLKEM768  AlgorithmID = "ML_KEM_768"
	AlgMLKEM1024 AlgorithmID = "ML_KEM_1024"
)
