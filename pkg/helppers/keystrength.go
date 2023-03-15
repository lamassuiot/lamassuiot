package helppers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/pkg/models"
)

func KeyStrengthMetadataFromCertificate(cert *x509.Certificate) models.KeyStrengthMetadata {
	var keyType models.KeyType
	var keyBits int
	switch cert.PublicKeyAlgorithm.String() {
	case "RSA":
		keyType = models.RSA
		keyBits = cert.PublicKey.(*rsa.PublicKey).N.BitLen()
	case "ECDSA":
		keyType = models.ECDSA
		keyBits = cert.PublicKey.(*ecdsa.PublicKey).Params().BitSize
	}

	var keyStrength models.KeyStrength = models.KeyStrengthLow
	switch keyType {
	case models.RSA:
		if keyBits < 2048 {
			keyStrength = models.KeyStrengthLow
		} else if keyBits >= 2048 && keyBits < 3072 {
			keyStrength = models.KeyStrengthMedium
		} else {
			keyStrength = models.KeyStrengthHigh
		}
	case models.ECDSA:
		if keyBits <= 128 {
			keyStrength = models.KeyStrengthLow
		} else if keyBits > 128 && keyBits < 256 {
			keyStrength = models.KeyStrengthMedium
		} else {
			keyStrength = models.KeyStrengthHigh
		}
	}

	return models.KeyStrengthMetadata{
		Type:     keyType,
		Bits:     keyBits,
		Strength: keyStrength,
	}
}
