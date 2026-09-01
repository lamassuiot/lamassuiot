package softwarev2

import (
	"crypto"
	"crypto/ecdh"
	"crypto/elliptic"
	"fmt"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// ---------------------------------------------------------------------------
// KeySpec -> material properties (family, size, curve). These drive key
// generation and material decode, independent of the per-operation algorithm.
// ---------------------------------------------------------------------------

func familyOfKeySpec(spec cryptoenginesv2.KeySpec) cryptoenginesv2.Family {
	switch spec {
	case cryptoenginesv2.KeySpecRSA2048, cryptoenginesv2.KeySpecRSA3072, cryptoenginesv2.KeySpecRSA4096:
		return cryptoenginesv2.FamilyRSA
	case cryptoenginesv2.KeySpecECCNISTP256, cryptoenginesv2.KeySpecECCNISTP384,
		cryptoenginesv2.KeySpecECCNISTP521, cryptoenginesv2.KeySpecECCSECGP256K1:
		return cryptoenginesv2.FamilyECDSA
	case cryptoenginesv2.KeySpecED25519:
		return cryptoenginesv2.FamilyEdDSA
	case cryptoenginesv2.KeySpecX25519:
		return cryptoenginesv2.FamilyECDH
	case cryptoenginesv2.KeySpecMLKEM768, cryptoenginesv2.KeySpecMLKEM1024:
		return cryptoenginesv2.FamilyMLKEM
	case cryptoenginesv2.KeySpecSymmetricDefault, cryptoenginesv2.KeySpecAES128, cryptoenginesv2.KeySpecAES192:
		return cryptoenginesv2.FamilyAES
	case cryptoenginesv2.KeySpecHMAC256, cryptoenginesv2.KeySpecHMAC384, cryptoenginesv2.KeySpecHMAC512:
		return cryptoenginesv2.FamilyHMAC
	}
	return ""
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func rsaModulusBits(spec cryptoenginesv2.KeySpec) (int, error) {
	switch spec {
	case cryptoenginesv2.KeySpecRSA2048:
		return 2048, nil
	case cryptoenginesv2.KeySpecRSA3072:
		return 3072, nil
	case cryptoenginesv2.KeySpecRSA4096:
		return 4096, nil
	}
	return 0, fmt.Errorf("soft: not an RSA key spec: %s", spec)
}

func ecdsaCurveOf(spec cryptoenginesv2.KeySpec) (elliptic.Curve, error) {
	switch spec {
	case cryptoenginesv2.KeySpecECCNISTP256:
		return elliptic.P256(), nil
	case cryptoenginesv2.KeySpecECCNISTP384:
		return elliptic.P384(), nil
	case cryptoenginesv2.KeySpecECCNISTP521:
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("soft: unsupported ECDSA key spec %s (secp256k1 needs an external dependency)", spec)
}

func ecdhCurveOf(spec cryptoenginesv2.KeySpec) (ecdh.Curve, error) {
	switch spec {
	case cryptoenginesv2.KeySpecX25519:
		return ecdh.X25519(), nil
	}
	return nil, fmt.Errorf("soft: unsupported ECDH key spec %s", spec)
}

func aesKeyBits(spec cryptoenginesv2.KeySpec) (int, error) {
	switch spec {
	case cryptoenginesv2.KeySpecAES128:
		return 128, nil
	case cryptoenginesv2.KeySpecAES192:
		return 192, nil
	case cryptoenginesv2.KeySpecSymmetricDefault:
		return 256, nil
	}
	return 0, fmt.Errorf("soft: unknown AES key spec %s", spec)
}

func hmacKeyBits(spec cryptoenginesv2.KeySpec) (int, error) {
	switch spec {
	case cryptoenginesv2.KeySpecHMAC256:
		return 256, nil
	case cryptoenginesv2.KeySpecHMAC384:
		return 384, nil
	case cryptoenginesv2.KeySpecHMAC512:
		return 512, nil
	}
	return 0, fmt.Errorf("soft: unknown HMAC key spec %s", spec)
}

// ---------------------------------------------------------------------------
// Per-operation AlgorithmID -> scheme / hash. These interpret the algorithm
// the caller passes at operation time (RSASSA_PSS_SHA_256, RSAES_OAEP_SHA_256,
// HMAC_SHA_256, ...).
// ---------------------------------------------------------------------------

// rsaSignParams reports the scheme ("pss" or "pkcs1v15") and hash for an RSA
// signing algorithm. ok is false when alg is not an RSA signing algorithm.
func rsaSignParams(alg cryptoenginesv2.AlgorithmID) (scheme string, hash crypto.Hash, ok bool) {
	switch alg {
	case cryptoenginesv2.AlgRSASSAPKCS1V15SHA256:
		return "pkcs1v15", crypto.SHA256, true
	case cryptoenginesv2.AlgRSASSAPKCS1V15SHA384:
		return "pkcs1v15", crypto.SHA384, true
	case cryptoenginesv2.AlgRSASSAPKCS1V15SHA512:
		return "pkcs1v15", crypto.SHA512, true
	case cryptoenginesv2.AlgRSASSAPSSSHA256:
		return "pss", crypto.SHA256, true
	case cryptoenginesv2.AlgRSASSAPSSSHA384:
		return "pss", crypto.SHA384, true
	case cryptoenginesv2.AlgRSASSAPSSSHA512:
		return "pss", crypto.SHA512, true
	}
	return "", 0, false
}

// rsaOAEPHash reports the OAEP hash for an RSA-OAEP encryption/wrap algorithm.
func rsaOAEPHash(alg cryptoenginesv2.AlgorithmID) (crypto.Hash, bool) {
	switch alg {
	case cryptoenginesv2.AlgRSAESOAEPSHA1:
		return crypto.SHA1, true
	case cryptoenginesv2.AlgRSAESOAEPSHA256:
		return crypto.SHA256, true
	case cryptoenginesv2.AlgRSAESOAEPSHA384:
		return crypto.SHA384, true
	case cryptoenginesv2.AlgRSAESOAEPSHA512:
		return crypto.SHA512, true
	}
	return 0, false
}

func isRSALegacyPKCS1Enc(alg cryptoenginesv2.AlgorithmID) bool {
	return alg == cryptoenginesv2.AlgRSAESPKCS1V15
}

// hmacHashOf reports the hash for an HMAC MAC algorithm.
func hmacHashOf(alg cryptoenginesv2.AlgorithmID) (crypto.Hash, bool) {
	switch alg {
	case cryptoenginesv2.AlgHMACSHA256:
		return crypto.SHA256, true
	case cryptoenginesv2.AlgHMACSHA384:
		return crypto.SHA384, true
	case cryptoenginesv2.AlgHMACSHA512:
		return crypto.SHA512, true
	}
	return 0, false
}
