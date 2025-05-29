package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func TestKeyStrengthMetadataFromCertificate(t *testing.T) {

	key1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	key2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	key3072, _ := rsa.GenerateKey(rand.Reader, 3072)

	rsaCert := &x509.Certificate{
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &key1024.PublicKey,
	}
	expected1 := models.KeyStrengthMetadata{
		Type:     models.KeyType(x509.RSA),
		Bits:     1024,
		Strength: models.KeyStrengthLow,
	}
	result1 := KeyStrengthMetadataFromCertificate(rsaCert)
	if result1 != expected1 {
		t.Errorf("Expected %v, but got %v", expected1, result1)
	}

	rsaCert = &x509.Certificate{
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &key2048.PublicKey,
	}
	expected2 := models.KeyStrengthMetadata{
		Type:     models.KeyType(x509.RSA),
		Bits:     2048,
		Strength: models.KeyStrengthMedium,
	}
	result2 := KeyStrengthMetadataFromCertificate(rsaCert)
	if result2 != expected2 {
		t.Errorf("Expected %v, but got %v", expected2, result2)
	}

	rsaCert = &x509.Certificate{
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &key3072.PublicKey,
	}
	expected3 := models.KeyStrengthMetadata{
		Type:     models.KeyType(x509.RSA),
		Bits:     3072,
		Strength: models.KeyStrengthHigh,
	}
	result3 := KeyStrengthMetadataFromCertificate(rsaCert)
	if result3 != expected3 {
		t.Errorf("Expected %v, but got %v", expected3, result3)
	}

	ecdsaCert := &x509.Certificate{
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey: &ecdsa.PublicKey{
			Curve: elliptic.P224(),
		},
	}
	expected5 := models.KeyStrengthMetadata{
		Type:     models.KeyType(x509.ECDSA),
		Bits:     224,
		Strength: models.KeyStrengthMedium,
	}
	result5 := KeyStrengthMetadataFromCertificate(ecdsaCert)
	if result5 != expected5 {
		t.Errorf("Expected %v, but got %v", expected5, result5)
	}

	ecdsaCert = &x509.Certificate{
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}
	expected6 := models.KeyStrengthMetadata{
		Type:     models.KeyType(x509.ECDSA),
		Bits:     256,
		Strength: models.KeyStrengthHigh,
	}
	result6 := KeyStrengthMetadataFromCertificate(ecdsaCert)
	if result6 != expected6 {
		t.Errorf("Expected %v, but got %v", expected6, result6)
	}
}
