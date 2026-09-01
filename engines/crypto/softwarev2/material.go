package softwarev2

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// generateMaterial creates a fresh keypair (or symmetric key) for the given
// KeySpec. The private part is returned in the form expected by encodePrivate;
// the public part is returned as crypto.PublicKey (or nil for symmetric).
func generateMaterial(spec cryptoenginesv2.KeySpec) (priv any, pub crypto.PublicKey, err error) {
	switch familyOfKeySpec(spec) {
	case cryptoenginesv2.FamilyRSA:
		size, err := rsaModulusBits(spec)
		if err != nil {
			return nil, nil, err
		}
		sk, err := rsa.GenerateKey(randomReader, size)
		if err != nil {
			return nil, nil, err
		}
		return sk, &sk.PublicKey, nil

	case cryptoenginesv2.FamilyECDSA:
		// One EC keypair serves both ECDSA signing and ECDH agreement.
		curve, err := ecdsaCurveOf(spec)
		if err != nil {
			return nil, nil, err
		}
		sk, err := ecdsa.GenerateKey(curve, randomReader)
		if err != nil {
			return nil, nil, err
		}
		return sk, &sk.PublicKey, nil

	case cryptoenginesv2.FamilyEdDSA:
		pubKey, sk, err := ed25519.GenerateKey(randomReader)
		if err != nil {
			return nil, nil, err
		}
		return sk, pubKey, nil

	case cryptoenginesv2.FamilyECDH:
		c, err := ecdhCurveOf(spec)
		if err != nil {
			return nil, nil, err
		}
		sk, err := c.GenerateKey(randomReader)
		if err != nil {
			return nil, nil, err
		}
		return sk, sk.PublicKey(), nil

	case cryptoenginesv2.FamilyMLKEM:
		switch spec {
		case cryptoenginesv2.KeySpecMLKEM768:
			dk, err := mlkem.GenerateKey768()
			if err != nil {
				return nil, nil, err
			}
			return dk, dk.EncapsulationKey(), nil
		case cryptoenginesv2.KeySpecMLKEM1024:
			dk, err := mlkem.GenerateKey1024()
			if err != nil {
				return nil, nil, err
			}
			return dk, dk.EncapsulationKey(), nil
		default:
			return nil, nil, fmt.Errorf("soft: ML-KEM variant %q not supported by stdlib (try CIRCL for 512)", spec)
		}

	case cryptoenginesv2.FamilyAES:
		bits, err := aesKeyBits(spec)
		if err != nil {
			return nil, nil, err
		}
		key := make([]byte, bits/8)
		if _, err := randomReader.Read(key); err != nil {
			return nil, nil, err
		}
		return key, nil, nil

	case cryptoenginesv2.FamilyHMAC:
		bits, err := hmacKeyBits(spec)
		if err != nil {
			return nil, nil, err
		}
		key := make([]byte, bits/8)
		if _, err := randomReader.Read(key); err != nil {
			return nil, nil, err
		}
		return key, nil, nil
	}
	return nil, nil, fmt.Errorf("soft: generation not implemented for %s", spec)
}

// encodePrivate produces the canonical byte form of a private key for
// persistence. Asymmetric: PKCS#8 DER. Symmetric: raw bytes. ML-KEM:
// seed bytes ("d || z" form).
func encodePrivate(spec cryptoenginesv2.KeySpec, priv any) ([]byte, error) {
	switch v := priv.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(v)
	case *ecdsa.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(v)
	case ed25519.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(v)
	case *ecdh.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(v)
	case *mlkem.DecapsulationKey768:
		return v.Bytes(), nil // 64-byte seed
	case *mlkem.DecapsulationKey1024:
		return v.Bytes(), nil
	case []byte:
		// AES / HMAC: raw key bytes.
		return append([]byte(nil), v...), nil
	}
	return nil, fmt.Errorf("soft: encodePrivate: unhandled type %T for %s", priv, spec)
}

// decodePrivate is the inverse of encodePrivate.
func decodePrivate(spec cryptoenginesv2.KeySpec, blob []byte) (any, error) {
	switch familyOfKeySpec(spec) {
	case cryptoenginesv2.FamilyRSA, cryptoenginesv2.FamilyECDSA, cryptoenginesv2.FamilyEdDSA, cryptoenginesv2.FamilyECDH:
		return x509.ParsePKCS8PrivateKey(blob)
	case cryptoenginesv2.FamilyMLKEM:
		switch spec {
		case cryptoenginesv2.KeySpecMLKEM768:
			return mlkem.NewDecapsulationKey768(blob)
		case cryptoenginesv2.KeySpecMLKEM1024:
			return mlkem.NewDecapsulationKey1024(blob)
		}
	case cryptoenginesv2.FamilyAES, cryptoenginesv2.FamilyHMAC:
		return append([]byte(nil), blob...), nil
	}
	return nil, fmt.Errorf("soft: decodePrivate: unhandled %s", spec)
}

// publicFromPrivate parses imported plain key bytes and returns the
// derived public key. Used by Import to populate KeyMetadata.PublicKey.
func publicFromPrivate(spec cryptoenginesv2.KeySpec, blob []byte) (crypto.PublicKey, error) {
	priv, err := decodePrivate(spec, blob)
	if err != nil {
		return nil, err
	}
	switch v := priv.(type) {
	case *rsa.PrivateKey:
		return &v.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &v.PublicKey, nil
	case ed25519.PrivateKey:
		return v.Public(), nil
	case *ecdh.PrivateKey:
		return v.PublicKey(), nil
	case *mlkem.DecapsulationKey768:
		return v.EncapsulationKey(), nil
	case *mlkem.DecapsulationKey1024:
		return v.EncapsulationKey(), nil
	case []byte:
		return nil, nil // symmetric: no public key
	}
	return nil, errors.New("soft: cannot derive public from imported material")
}
