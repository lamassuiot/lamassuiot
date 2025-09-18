package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"
	"time"

	cmodels "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func TestGenerateSelfSignedCA(t *testing.T) {
	// Caso de prueba 1: keyType es x509.RSA
	expirationTime := time.Hour * 24 * 365 // 1 año
	cert, key, err := GenerateSelfSignedCA(x509.RSA, expirationTime, "MyCA")
	if err != nil {
		t.Errorf("Error generando el certificado: %v", err)
	}

	// Verificar que el certificado sea válido
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("El certificado no es válido: %v", err)
	}

	// Verificar que el certificado tenga la clave privada correspondiente
	switch key := key.(type) {
	case *rsa.PrivateKey:
		if !reflect.DeepEqual(&key.PublicKey, cert.PublicKey) {
			t.Errorf("La clave privada no coincide con la clave pública del certificado")
		}
	case *ecdsa.PrivateKey:
		if !reflect.DeepEqual(&key.PublicKey, cert.PublicKey) {
			t.Errorf("La clave privada no coincide con la clave pública del certificado")
		}
	default:
		t.Errorf("Tipo de clave no válido")
	}

	// Caso de prueba 2: keyType es x509.ECDSA
	cert, key, err = GenerateSelfSignedCA(x509.ECDSA, expirationTime, "MyCA")
	if err != nil {
		t.Errorf("Error generando el certificado: %v", err)
	}

	// Verificar que el certificado sea válido
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("El certificado no es válido: %v", err)
	}

	// Verificar que el certificado tenga la clave privada correspondiente
	switch key := key.(type) {
	case *rsa.PrivateKey:
		if !reflect.DeepEqual(&key.PublicKey, cert.PublicKey) {
			t.Errorf("La clave privada no coincide con la clave pública del certificado")
		}
	case *ecdsa.PrivateKey:
		if !reflect.DeepEqual(&key.PublicKey, cert.PublicKey) {
			t.Errorf("La clave privada no coincide con la clave pública del certificado")
		}
	default:
		t.Errorf("Tipo de clave no válido")
	}
}

func TestGenerateCertificateRequest(t *testing.T) {
	subject := cmodels.Subject{
		CommonName:       "example.com",
		Organization:     "Acme Inc",
		OrganizationUnit: "IT",
	}

	// Case 1: key is *rsa.PrivateKey
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Failed to generate RSA key: %v", err)
		return
	}

	csr, err := GenerateCertificateRequest(subject, rsaKey)
	if err != nil {
		t.Errorf("Failed to generate certificate request: %v", err)
		return
	}

	// Verify the subject of the CSR
	if csr.Subject.CommonName != subject.CommonName {
		t.Errorf("Unexpected CommonName in CSR. Expected: %s, Got: %s", subject.CommonName, csr.Subject.CommonName)
	}

	// Case 2: key is *ecdsa.PrivateKey
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate ECDSA key: %v", err)
		return
	}

	csr, err = GenerateCertificateRequest(subject, ecdsaKey)
	if err != nil {
		t.Errorf("Failed to generate certificate request: %v", err)
		return
	}

	// Verify the subject of the CSR
	if csr.Subject.CommonName != subject.CommonName {
		t.Errorf("Unexpected CommonName in CSR. Expected: %s, Got: %s", subject.CommonName, csr.Subject.CommonName)
	}
}

func TestDecryptWithPrivateKey(t *testing.T) {
	// Generate a random RSA key pair for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Generate a random plaintext
	plaintext := []byte("Hello, World!")

	// Encrypt the plaintext using the public key
	ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, &privKey.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt plaintext: %v", err)
	}

	// Decrypt the ciphertext using the private key
	decrypted, err := DecryptWithPrivateKey(ciphertext, privKey)
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext: %v", err)
	}

	// Verify that the decrypted plaintext matches the original plaintext
	if !reflect.DeepEqual(decrypted, plaintext) {
		t.Errorf("Decrypted plaintext does not match original plaintext")
	}
}
func TestEncryptWithPublicKey(t *testing.T) {
	// Generate a random RSA key pair for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Generate a random plaintext
	plaintext := []byte("Hello, World!")

	// Encrypt the plaintext using the public key
	ciphertext, err := EncryptWithPublicKey(plaintext, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encrypt plaintext: %v", err)
	}

	// Decrypt the ciphertext using the private key
	decrypted, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, privKey, ciphertext, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext: %v", err)
	}

	// Verify that the decrypted plaintext matches the original plaintext
	if !reflect.DeepEqual(decrypted, plaintext) {
		t.Errorf("Decrypted plaintext does not match original plaintext")
	}
}

func TestValidateCertAndPrivKey(t *testing.T) {
	// Generate a self-signed certificate and private keys for testing
	expirationTime := time.Hour * 24 * 365 // 1 year
	cert, rsaKey, err := GenerateSelfSignedCA(x509.RSA, expirationTime, "MyCA")
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate and RSA private key: %v", err)
	}

	certEc, ecKey, err := GenerateSelfSignedCA(x509.ECDSA, expirationTime, "MyCA")
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate and RSA private key: %v", err)
	}

	// Case 1: RSA private key matches the certificate
	rsaPrivateKey, ok := rsaKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Failed to perform type assertion for rsaKey")
	}
	valid, err := ValidateCertAndPrivKey(cert, rsaPrivateKey, nil)
	if err != nil {
		t.Errorf("Failed to validate RSA private key: %v", err)
	}
	if !valid {
		t.Errorf("Expected RSA private key to be valid, but it was not")
	}

	// Case 2: ECDSA private key matches the certificate
	valid, err = ValidateCertAndPrivKey(certEc, nil, ecKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Errorf("Failed to validate ECDSA private key: %v", err)
	}
	if !valid {
		t.Errorf("Expected ECDSA private key to be valid, but it was not")
	}

	// Case 3: RSA private key does not match the certificate
	invalidRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate invalid RSA private key: %v", err)
	}
	valid, err = ValidateCertAndPrivKey(cert, invalidRSAKey, nil)
	if err != nil {
		t.Errorf("Failed to validate RSA private key: %v", err)
	}
	if valid {
		t.Errorf("Expected RSA private key to be invalid, but it was valid")
	}

	// Case 4: ECDSA private key does not match the certificate
	invalidECKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate invalid ECDSA private key: %v", err)
	}
	valid, err = ValidateCertAndPrivKey(certEc, nil, invalidECKey)
	if err != nil {
		t.Errorf("Failed to validate ECDSA private key: %v", err)
	}
	if valid {
		t.Errorf("Expected ECDSA private key to be invalid, but it was valid")
	}

	// Case 5: Both RSA and ECDSA private keys are nil
	valid, err = ValidateCertAndPrivKey(cert, nil, nil)
	if err == nil {
		t.Errorf("Expected error when both RSA and ECDSA private keys are nil, but got nil")
	}
	if valid {
		t.Errorf("Expected both RSA and ECDSA private keys to be invalid, but they were valid")
	}
}
func TestCalculateRSAKeySizes(t *testing.T) {
	keyMin := 128
	keyMax := 4096
	expectedKeySizes := []int{128, 256, 384, 512, 640, 768, 896, 1024, 2048, 3072, 4096}

	keySizes := CalculateRSAKeySizes(keyMin, keyMax)

	if !reflect.DeepEqual(keySizes, expectedKeySizes) {
		t.Errorf("Unexpected key sizes. Expected: %v, Got: %v", expectedKeySizes, keySizes)
	}
}

func TestCalculateECDSAKeySizes(t *testing.T) {
	// Case 1: keyMin is less than 224 and KeyMax is greater than 224
	keyMin := 128
	keyMax := 256
	expectedKeySizes := []int{128, 224}

	keySizes := CalculateECDSAKeySizes(keyMin, keyMax)

	if !reflect.DeepEqual(keySizes, expectedKeySizes) {
		t.Errorf("Unexpected key sizes. Expected: %v, Got: %v", expectedKeySizes, keySizes)
	}

	// Case 2: keyMin is less than 256 and KeyMax is greater than 256
	keyMin = 224
	keyMax = 384
	expectedKeySizes = []int{224, 256}

	keySizes = CalculateECDSAKeySizes(keyMin, keyMax)

	if !reflect.DeepEqual(keySizes, expectedKeySizes) {
		t.Errorf("Unexpected key sizes. Expected: %v, Got: %v", expectedKeySizes, keySizes)
	}

	// Case 3: keyMin is less than 384 and KeyMax is greater than 384
	keyMin = 256
	keyMax = 521
	expectedKeySizes = []int{256, 384, 521}

	keySizes = CalculateECDSAKeySizes(keyMin, keyMax)

	if !reflect.DeepEqual(keySizes, expectedKeySizes) {
		t.Errorf("Unexpected key sizes. Expected: %v, Got: %v", expectedKeySizes, keySizes)
	}

	// Case 4: keyMin is less than 521 and KeyMax is equal to 521
	keyMin = 384
	keyMax = 521
	expectedKeySizes = []int{384, 521}

	keySizes = CalculateECDSAKeySizes(keyMin, keyMax)

	if !reflect.DeepEqual(keySizes, expectedKeySizes) {
		t.Errorf("Unexpected key sizes. Expected: %v, Got: %v", expectedKeySizes, keySizes)
	}

	// Case 5: keyMin is equal to KeyMax
	keyMin = 256
	keyMax = 256
	expectedKeySizes = []int{256}

	keySizes = CalculateECDSAKeySizes(keyMin, keyMax)

	if !reflect.DeepEqual(keySizes, expectedKeySizes) {
		t.Errorf("Unexpected key sizes. Expected: %v, Got: %v", expectedKeySizes, keySizes)
	}
}
func TestEqualPublicKeys(t *testing.T) {
	// Test case 1: Equal RSA public keys
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	rsaKey2 := &rsaKey1.PublicKey

	if !EqualPublicKeys(&rsaKey1.PublicKey, rsaKey2) {
		t.Errorf("Expected RSA public keys to be equal, but they were not")
	}

	// Test case 2: Different RSA public keys
	rsaKey3, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	if EqualPublicKeys(&rsaKey1.PublicKey, &rsaKey3.PublicKey) {
		t.Errorf("Expected RSA public keys to be different, but they were equal")
	}

	// Test case 3: Equal ECDSA public keys
	ecdsaKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	ecdsaKey2 := &ecdsaKey1.PublicKey

	if !EqualPublicKeys(&ecdsaKey1.PublicKey, ecdsaKey2) {
		t.Errorf("Expected ECDSA public keys to be equal, but they were not")
	}

	// Test case 4: Different ECDSA public keys
	ecdsaKey3, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	if EqualPublicKeys(&ecdsaKey1.PublicKey, &ecdsaKey3.PublicKey) {
		t.Errorf("Expected ECDSA public keys to be different, but they were equal")
	}

	// Test case 5: Different types of public keys
	if EqualPublicKeys(&rsaKey1.PublicKey, &ecdsaKey1.PublicKey) {
		t.Errorf("Expected public keys of different types to be different, but they were equal")
	}
}

func TestExtractKeyUsageFromCSR_KeyUsageOnly(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subject := cmodels.Subject{CommonName: "test"}
	kuExt, err := GenerateKeyUsagePKIExtension(x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign)
	if err != nil {
		t.Fatalf("failed to generate key usage extension: %v", err)
	}
	csr, err := GenerateCertificateRequestWithExtensions(subject, []pkix.Extension{kuExt}, priv)
	if err != nil {
		t.Fatalf("failed to generate CSR: %v", err)
	}
	ku, eku, err := ExtractKeyUsageFromCSR(csr)
	if err != nil {
		t.Fatalf("ExtractKeyUsageFromCSR error: %v", err)
	}
	if ku&x509.KeyUsageDigitalSignature == 0 || ku&x509.KeyUsageCertSign == 0 {
		t.Errorf("unexpected key usage bits: %v", ku)
	}
	if len(eku) != 0 {
		t.Errorf("expected no extended key usage, got: %v", eku)
	}
}

func TestExtractKeyUsageFromCSR_ExtendedKeyUsageOnly(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subject := cmodels.Subject{CommonName: "test"}
	ekuExt, err := GenerateExtendedKeyUsagePKIExtension([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	if err != nil {
		t.Fatalf("failed to generate extended key usage extension: %v", err)
	}
	csr, err := GenerateCertificateRequestWithExtensions(subject, []pkix.Extension{ekuExt}, priv)
	if err != nil {
		t.Fatalf("failed to generate CSR: %v", err)
	}
	ku, eku, err := ExtractKeyUsageFromCSR(csr)
	if err != nil {
		t.Fatalf("ExtractKeyUsageFromCSR error: %v", err)
	}
	if ku != 0 {
		t.Errorf("expected key usage to be zero, got: %v", ku)
	}
	if len(eku) != 2 {
		t.Errorf("expected 2 extended key usages, got: %v", eku)
	}
}

func TestExtractKeyUsageFromCSR_BothExtensions(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subject := cmodels.Subject{CommonName: "test"}
	kuExt, _ := GenerateKeyUsagePKIExtension(x509.KeyUsageDigitalSignature)
	ekuExt, _ := GenerateExtendedKeyUsagePKIExtension([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})
	csr, err := GenerateCertificateRequestWithExtensions(subject, []pkix.Extension{kuExt, ekuExt}, priv)
	if err != nil {
		t.Fatalf("failed to generate CSR: %v", err)
	}
	ku, eku, err := ExtractKeyUsageFromCSR(csr)
	if err != nil {
		t.Fatalf("ExtractKeyUsageFromCSR error: %v", err)
	}
	if ku&x509.KeyUsageDigitalSignature == 0 {
		t.Errorf("expected digital signature key usage, got: %v", ku)
	}
	if len(eku) != 1 || eku[0] != x509.ExtKeyUsageCodeSigning {
		t.Errorf("expected code signing EKU, got: %v", eku)
	}
}

func TestExtractKeyUsageFromCSR_InvalidKeyUsageExtension(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subject := cmodels.Subject{CommonName: "test"}
	// Invalid ASN.1 for KeyUsage
	invalidKU := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 15},
		Value: []byte{0x01, 0x02, 0x03},
	}
	csr, err := GenerateCertificateRequestWithExtensions(subject, []pkix.Extension{invalidKU}, priv)
	if err != nil {
		t.Fatalf("failed to generate CSR: %v", err)
	}
	_, _, err = ExtractKeyUsageFromCSR(csr)
	if err == nil {
		t.Errorf("expected error for invalid key usage extension")
	}
}

func TestExtractKeyUsageFromCSR_UnknownEKUOID(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subject := cmodels.Subject{CommonName: "test"}
	// Use a made-up OID for EKU
	ekuASN1, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 2, 3, 4, 5}})
	ekuExt := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
		Value: ekuASN1,
	}
	csr, err := GenerateCertificateRequestWithExtensions(subject, []pkix.Extension{ekuExt}, priv)
	if err != nil {
		t.Fatalf("failed to generate CSR: %v", err)
	}
	_, eku, err := ExtractKeyUsageFromCSR(csr)
	if err != nil {
		t.Fatalf("ExtractKeyUsageFromCSR error: %v", err)
	}
	if len(eku) != 0 {
		t.Errorf("expected no recognized EKU, got: %v", eku)
	}
}
