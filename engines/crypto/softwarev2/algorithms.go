package softwarev2

import (
	"crypto"
	"crypto/ecdh"
	"crypto/elliptic"
	"fmt"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

func familyOf(alg cryptoenginesv2.AlgorithmID) cryptoenginesv2.Family {
	switch alg {
	case "RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PKCS1_V1_5_SHA_384", "RSASSA_PKCS1_V1_5_SHA_512",
		"RSASSA_PSS_SHA_256", "RSASSA_PSS_SHA_384", "RSASSA_PSS_SHA_512":
		return cryptoenginesv2.FamilyRSA
	case "ECDSA_SHA_256", "ECDSA_SHA_384", "ECDSA_SHA_512", "ECDSA_SHA_256_ECC_SECG_P256K1":
		return cryptoenginesv2.FamilyECDSA
	case "ED25519":
		return cryptoenginesv2.FamilyEdDSA
	case "ECDH_NIST_P256", "ECDH_NIST_P384", "ECDH_NIST_P521", "ECDH_X25519":
		return cryptoenginesv2.FamilyECDH
	case "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024":
		return cryptoenginesv2.FamilyMLKEM
	case "AES_GCM_128", "AES_GCM_192", "AES_GCM_256", "AES_CBC_128", "AES_CBC_192", "AES_CBC_256":
		return cryptoenginesv2.FamilyAES
	case "HMAC_SHA_256", "HMAC_SHA_384", "HMAC_SHA_512":
		return cryptoenginesv2.FamilyHMAC
	}
	// RSA-OAEP and PKCS#1 v1.5 entries include size suffixes; family-prefix match.
	if hasPrefix(string(alg), "RSAES_OAEP_") || hasPrefix(string(alg), "RSAES_PKCS1_V1_5_") {
		return cryptoenginesv2.FamilyRSA
	}
	if hasPrefix(string(alg), "AES_KEY_WRAP_") {
		return cryptoenginesv2.FamilyAESKW
	}
	return ""
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
func hasSuffix(s, p string) bool { return len(s) >= len(p) && s[len(s)-len(p):] == p }

func rsaModulusBits(alg cryptoenginesv2.AlgorithmID) (int, error) {
	switch alg {
	case "RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PSS_SHA_256",
		"RSAES_OAEP_SHA_1_2048", "RSAES_OAEP_SHA_256_2048", "RSAES_OAEP_SHA_384_2048", "RSAES_OAEP_SHA_512_2048",
		"RSAES_PKCS1_V1_5_2048":
		return 2048, nil
	case "RSASSA_PKCS1_V1_5_SHA_384", "RSASSA_PSS_SHA_384",
		"RSAES_OAEP_SHA_1_3072", "RSAES_OAEP_SHA_256_3072", "RSAES_OAEP_SHA_384_3072", "RSAES_OAEP_SHA_512_3072",
		"RSAES_PKCS1_V1_5_3072":
		return 3072, nil
	case "RSASSA_PKCS1_V1_5_SHA_512", "RSASSA_PSS_SHA_512",
		"RSAES_OAEP_SHA_1_4096", "RSAES_OAEP_SHA_256_4096", "RSAES_OAEP_SHA_384_4096", "RSAES_OAEP_SHA_512_4096",
		"RSAES_PKCS1_V1_5_4096":
		return 4096, nil
	}
	return 0, fmt.Errorf("soft: unknown RSA algorithm %s", alg)
}

func ecdsaCurveOf(alg cryptoenginesv2.AlgorithmID) (elliptic.Curve, error) {
	switch alg {
	case "ECDSA_SHA_256":
		return elliptic.P256(), nil
	case "ECDSA_SHA_384":
		return elliptic.P384(), nil
	case "ECDSA_SHA_512":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("soft: unsupported ECDSA algorithm %s", alg)
}

func ecdhCurveOf(alg cryptoenginesv2.AlgorithmID) (ecdh.Curve, error) {
	switch alg {
	case "ECDH_NIST_P256":
		return ecdh.P256(), nil
	case "ECDH_NIST_P384":
		return ecdh.P384(), nil
	case "ECDH_NIST_P521":
		return ecdh.P521(), nil
	case "ECDH_X25519":
		return ecdh.X25519(), nil
	}
	return nil, fmt.Errorf("soft: unsupported ECDH algorithm %s", alg)
}

func aesKeyBits(alg cryptoenginesv2.AlgorithmID) (int, error) {
	switch alg {
	case "AES_GCM_128", "AES_CBC_128":
		return 128, nil
	case "AES_GCM_192", "AES_CBC_192":
		return 192, nil
	case "AES_GCM_256", "AES_CBC_256":
		return 256, nil
	}
	return 0, fmt.Errorf("soft: unknown AES algorithm %s", alg)
}

func hmacKeyBits(alg cryptoenginesv2.AlgorithmID) (int, error) {
	switch alg {
	case "HMAC_SHA_256":
		return 256, nil
	case "HMAC_SHA_384":
		return 384, nil
	case "HMAC_SHA_512":
		return 512, nil
	}
	return 0, fmt.Errorf("soft: unknown HMAC algorithm %s", alg)
}

// rsaHashFor extracts the canonical hash for a given RSA algorithm ID.
// Returned for use by rsaHandle.SignContext when opts.HashFunc() is zero.
func rsaHashFor(alg cryptoenginesv2.AlgorithmID) crypto.Hash {
	switch alg {
	case "RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PSS_SHA_256":
		return crypto.SHA256
	case "RSASSA_PKCS1_V1_5_SHA_384", "RSASSA_PSS_SHA_384":
		return crypto.SHA384
	case "RSASSA_PKCS1_V1_5_SHA_512", "RSASSA_PSS_SHA_512":
		return crypto.SHA512
	}
	if hasPrefix(string(alg), "RSAES_OAEP_SHA_1_") {
		return crypto.SHA1
	}
	if hasPrefix(string(alg), "RSAES_OAEP_SHA_256_") {
		return crypto.SHA256
	}
	if hasPrefix(string(alg), "RSAES_OAEP_SHA_384_") {
		return crypto.SHA384
	}
	if hasPrefix(string(alg), "RSAES_OAEP_SHA_512_") {
		return crypto.SHA512
	}
	return 0
}
