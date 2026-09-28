package cryptoenginesv2

// KeySpec describes the key *material* — what gets generated and stored —
// independent of the scheme/hash used at operation time. This mirrors the
// AWS KMS model: a key has one KeySpec (e.g. RSA_2048) and a set of authorized
// operations, while the per-operation algorithm (e.g. RSASSA_PSS_SHA_256) is
// chosen at sign/encrypt time. One KeySpec therefore serves many AlgorithmIDs.
type KeySpec string

const (
	// RSA — one spec per modulus size. Serves every RSASSA_* signing
	// algorithm and every RSAES_* encryption algorithm of the same size.
	KeySpecRSA2048 KeySpec = "RSA_2048"
	KeySpecRSA3072 KeySpec = "RSA_3072"
	KeySpecRSA4096 KeySpec = "RSA_4096"

	// Elliptic curve — one EC keypair serves both ECDSA signing and ECDH
	// key agreement (see stdlib ecdsa.PrivateKey.ECDH()).
	KeySpecECCNISTP256   KeySpec = "ECC_NIST_P256"
	KeySpecECCNISTP384   KeySpec = "ECC_NIST_P384"
	KeySpecECCNISTP521   KeySpec = "ECC_NIST_P521"
	KeySpecECCSECGP256K1 KeySpec = "ECC_SECG_P256K1"

	// EdDSA / X25519 (extensions beyond AWS KMS).
	KeySpecED25519 KeySpec = "ED25519"
	KeySpecX25519  KeySpec = "X25519" // key agreement only

	// Symmetric. SYMMETRIC_DEFAULT is AES-256 (AWS convention).
	KeySpecSymmetricDefault KeySpec = "SYMMETRIC_DEFAULT"
	KeySpecAES128           KeySpec = "AES_128"
	KeySpecAES192           KeySpec = "AES_192"

	// HMAC.
	KeySpecHMAC256 KeySpec = "HMAC_256"
	KeySpecHMAC384 KeySpec = "HMAC_384"
	KeySpecHMAC512 KeySpec = "HMAC_512"

	// ML-KEM (FIPS 203) — encapsulation keys (extension beyond AWS KMS).
	KeySpecMLKEM768  KeySpec = "ML_KEM_768"
	KeySpecMLKEM1024 KeySpec = "ML_KEM_1024"
)

// KeyUsage is a coarse, API-facing grouping of operations. It is a convenience
// over the fine-grained Operations set: a CreateKey request may declare usages
// which the Service expands into Operations before persisting. Unlike AWS KMS,
// a key MAY declare multiple usages (the resulting Operations set is the union).
type KeyUsage string

const (
	UsageSignVerify        KeyUsage = "SIGN_VERIFY"
	UsageEncryptDecrypt    KeyUsage = "ENCRYPT_DECRYPT"
	UsageWrapUnwrap        KeyUsage = "WRAP_UNWRAP"
	UsageGenerateVerifyMAC KeyUsage = "GENERATE_VERIFY_MAC"
	UsageKeyAgreement      KeyUsage = "KEY_AGREEMENT"
	UsageEncapDecap        KeyUsage = "ENCAPSULATE_DECAPSULATE"
)

// usageOperations maps each KeyUsage to the fine-grained operations it grants.
var usageOperations = map[KeyUsage][]Operation{
	UsageSignVerify:        {OpSign, OpVerify},
	UsageEncryptDecrypt:    {OpEncrypt, OpDecrypt},
	UsageWrapUnwrap:        {OpWrapKey, OpUnwrapKey},
	UsageGenerateVerifyMAC: {OpMAC, OpVerifyMAC},
	UsageKeyAgreement:      {OpAgreeKey, OpDeriveKey},
	UsageEncapDecap:        {OpEncapsulate, OpDecapsulate},
}

// ExpandUsages returns the deduplicated union of operations granted by the
// given usages, preserving a stable order. Unknown usages contribute nothing.
func ExpandUsages(usages []KeyUsage) []Operation {
	seen := make(map[Operation]struct{})
	out := make([]Operation, 0, len(usages)*2)
	for _, u := range usages {
		for _, op := range usageOperations[u] {
			if _, dup := seen[op]; dup {
				continue
			}
			seen[op] = struct{}{}
			out = append(out, op)
		}
	}
	return out
}
