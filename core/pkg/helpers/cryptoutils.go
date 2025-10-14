package helpers

import (
	"cloudflare/circl/sign/mldsa/mldsa44"
	"cloudflare/circl/sign/mldsa/mldsa65"
	"cloudflare/circl/sign/mldsa/mldsa87"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/google/uuid"
	cmodels "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	log "github.com/sirupsen/logrus"
)

// Map x509.ExtKeyUsage to their corresponding OIDs (this is a copy of the internal mapping in crypto/x509, but we need the OIDs here.
// So we replicate it here since it's not exposed)

var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}
var oidExtExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

var oidExtKeyUsageAny = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
var oidExtKeyUsageServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
var oidExtKeyUsageClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
var oidExtKeyUsageCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
var oidExtKeyUsageEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
var oidExtKeyUsageIPSECEndSystem = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
var oidExtKeyUsageIPSECTunnel = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
var oidExtKeyUsageIPSECUser = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
var oidExtKeyUsageTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
var oidExtKeyUsageOCSPSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
var oidExtKeyUsageMicrosoftServerGatedCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
var oidExtKeyUsageNetscapeServerGatedCrypto = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
var oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
var oidExtKeyUsageMicrosoftKernelCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
var extKeyUsageOIDs = map[x509.ExtKeyUsage]asn1.ObjectIdentifier{
	x509.ExtKeyUsageAny:                            oidExtKeyUsageAny,
	x509.ExtKeyUsageServerAuth:                     oidExtKeyUsageServerAuth,
	x509.ExtKeyUsageClientAuth:                     oidExtKeyUsageClientAuth,
	x509.ExtKeyUsageCodeSigning:                    oidExtKeyUsageCodeSigning,
	x509.ExtKeyUsageEmailProtection:                oidExtKeyUsageEmailProtection,
	x509.ExtKeyUsageIPSECEndSystem:                 oidExtKeyUsageIPSECEndSystem,
	x509.ExtKeyUsageIPSECTunnel:                    oidExtKeyUsageIPSECTunnel,
	x509.ExtKeyUsageIPSECUser:                      oidExtKeyUsageIPSECUser,
	x509.ExtKeyUsageTimeStamping:                   oidExtKeyUsageTimeStamping,
	x509.ExtKeyUsageOCSPSigning:                    oidExtKeyUsageOCSPSigning,
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     oidExtKeyUsageMicrosoftServerGatedCrypto,
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      oidExtKeyUsageNetscapeServerGatedCrypto,
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: oidExtKeyUsageMicrosoftCommercialCodeSigning,
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     oidExtKeyUsageMicrosoftKernelCodeSigning,
}

var ekuOIDToExt = func() map[string]x509.ExtKeyUsage {
	m := make(map[string]x509.ExtKeyUsage, len(extKeyUsageOIDs))
	for ext, oid := range extKeyUsageOIDs {
		m[oid.String()] = ext
	}
	return m
}()

//Cammbio de la función para definir la longevidad de la expiración de la CA.

func GenerateSelfSignedCA(keyType x509.PublicKeyAlgorithm, expirationTime time.Duration, commonName string) (*x509.Certificate, any, error) {
	key, pubKey, err := generateKey(keyType)
	if err != nil {
		return nil, nil, err
	}

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	template := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              (time.Now().Add(expirationTime)),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsage(x509.ExtKeyUsageOCSPSigning),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte(uuid.NewString()),
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func GenerateSelfSignedChameleonCA(deltaKeyType, baseKeyType x509.PublicKeyAlgorithm, expirationTime time.Duration, commonName string) (*x509.Certificate, crypto.Signer, crypto.Signer, error) {
	deltaKey, deltaPubKey, err := generateKey(deltaKeyType)
	if err != nil {
		return nil, nil, nil, err
	}
	baseKey, basePubKey, err := generateKey(baseKeyType)
	if err != nil {
		return nil, nil, nil, err
	}

	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	template := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              (time.Now().Add(expirationTime)),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsage(x509.ExtKeyUsageOCSPSigning),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte(uuid.NewString()),
		IsCA:                  true,
	}

	derBytes, err := x509.CreateChameleonCertificate(rand.Reader, &template, &template, &template, &template, deltaPubKey, basePubKey, deltaKey, baseKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, deltaKey, baseKey, nil
}

func generateKey(keyType x509.PublicKeyAlgorithm) (crypto.Signer, crypto.PublicKey, error) {
	var key crypto.Signer
	var pubKey crypto.PublicKey

	switch keyType {
	case x509.RSA:
		rsaKey, err := GenerateRSAKey(2048)
		if err != nil {
			return nil, nil, err
		}
		key = rsaKey
		pubKey = &rsaKey.PublicKey
	case x509.ECDSA:
		eccKey, err := GenerateECDSAKey(elliptic.P224())
		if err != nil {
			return nil, nil, err
		}
		key = eccKey
		pubKey = &eccKey.PublicKey
	case x509.MLDSA:
		mldsaKey, err := GenerateMLDSAKey(65)
		if err != nil {
			return nil, nil, err
		}
		key = mldsaKey
		pubKey = mldsaKey.Public()
	case x509.Ed25519:
		ed25519Key, err := GenerateEd25519Key()
		if err != nil {
			return nil, nil, err
		}
		key = ed25519Key
		pubKey = ed25519Key.Public()
	}

	return key, pubKey, nil
}

// defined to generate certificates with RSA and ECDSA keys
func GenerateCertificateRequest(subject cmodels.Subject, key any) (*x509.CertificateRequest, error) {
	template := x509.CertificateRequest{
		Subject: SubjectToPkixName(subject),
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	return csr, err
}

// defined to generate certificates with RSA and ECDSA keys
func GenerateCertificateRequestWithExtensions(subject cmodels.Subject, extensions []pkix.Extension, key any) (*x509.CertificateRequest, error) {
	template := x509.CertificateRequest{
		Subject:         SubjectToPkixName(subject),
		ExtraExtensions: extensions,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	return csr, err
}

func ExtractKeyUsageFromCSR(csr *x509.CertificateRequest) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	// BIT STRING (MSB-first) -> Go x509.KeyUsage bitmask.
	// Only decodes the 9 RFC 5280 bits [0..8].
	bitStringToKeyUsage := func(bs asn1.BitString) x509.KeyUsage {
		var ku x509.KeyUsage
		for i := 0; i <= 8 && i < bs.BitLength; i++ {
			byteIdx := i / 8
			if byteIdx >= len(bs.Bytes) {
				break
			}
			bitInByte := 7 - (i % 8) // MSB-first within each byte
			if bs.Bytes[byteIdx]&(1<<uint(bitInByte)) != 0 {
				ku |= 1 << uint(i)
			}
		}
		return ku
	}

	var kuMask x509.KeyUsage
	var ekuList []x509.ExtKeyUsage

	all := append([]pkix.Extension{}, csr.Extensions...)
	all = append(all, csr.ExtraExtensions...)

	for _, e := range all {
		switch {
		case e.Id.Equal(oidExtKeyUsage):
			var bs asn1.BitString
			if _, err := asn1.Unmarshal(e.Value, &bs); err != nil {
				return 0, nil, fmt.Errorf("unmarshal KeyUsage: %w", err)
			}
			kuMask = bitStringToKeyUsage(bs)

		case e.Id.Equal(oidExtExtendedKeyUsage):
			var oids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(e.Value, &oids); err != nil {
				return 0, nil, fmt.Errorf("unmarshal ExtendedKeyUsage: %w", err)
			}
			for _, oid := range oids {
				if ext, ok := ekuOIDToExt[oid.String()]; ok {
					ekuList = append(ekuList, ext)
				}
				// else: unknown/custom EKU OID -> silently skip
			}
		}
	}

	return kuMask, ekuList, nil
}

func GenerateKeyUsagePKIExtension(keyUsage x509.KeyUsage) (pkix.Extension, error) {
	if keyUsage == 0 {
		return pkix.Extension{}, fmt.Errorf("key usage cannot be zero")
	}

	// RFC 5280 defines KeyUsage bits 0..8 (encipherOnly..decipherOnly via mapping below).
	// If anything above bit 8 is set, reject to avoid emitting non-standard bits.
	const maxBit = 8
	if keyUsage&(^(x509.KeyUsage((1 << (maxBit + 1)) - 1))) != 0 {
		return pkix.Extension{}, fmt.Errorf("unsupported key usage bits above %d set", maxBit)
	}

	// Find highest set bit (0..8)
	highest := -1
	for i := 0; i <= maxBit; i++ {
		if keyUsage&(1<<uint(i)) != 0 {
			highest = i
		}
	}
	if highest < 0 {
		return pkix.Extension{}, fmt.Errorf("key usage had no recognized bits")
	}

	// Bytes needed and MSB-first packing per DER BIT STRING rules
	n := (highest/8 + 1)
	b := make([]byte, n)
	for i := 0; i <= highest; i++ {
		if keyUsage&(1<<uint(i)) == 0 {
			continue
		}
		byteIdx := i / 8
		bitInByte := 7 - (i % 8) // MSB-first
		b[byteIdx] |= 1 << uint(bitInByte)
	}

	bitLen := highest + 1
	der, err := asn1.Marshal(asn1.BitString{Bytes: b, BitLength: bitLen})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal key usage: %w", err)
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // keyUsage
		Critical: true,
		Value:    der,
	}, nil
}

func GenerateExtendedKeyUsagePKIExtension(extKeyUsages []x509.ExtKeyUsage) (pkix.Extension, error) {
	var extKeyUsageOIDsList []asn1.ObjectIdentifier
	for _, eku := range extKeyUsages {
		if oid, found := extKeyUsageOIDs[eku]; found {
			extKeyUsageOIDsList = append(extKeyUsageOIDsList, oid)
		}
	}

	// Marshal to ASN.1 SEQUENCE
	extKeyUsageASN1, err := asn1.Marshal(extKeyUsageOIDsList)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal extended key usage: %v", err)
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, // Extended Key Usage OID
		Critical: false,
		Value:    extKeyUsageASN1,
	}, nil
}

func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return privkey, nil
}

func GenerateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	privkey, err := ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		return nil, err
	}

	return privkey, nil
}

func GenerateMLDSAKey(dimensions int) (crypto.Signer, error) {
	var key crypto.Signer
	var err error
	switch dimensions {
	case 44:
		_, key, err = mldsa44.GenerateKey(rand.Reader)
	case 65:
		_, key, err = mldsa65.GenerateKey(rand.Reader)
	case 87:
		_, key, err = mldsa87.GenerateKey(rand.Reader)
	default:
		err = errors.New("unsupported dimensions")
	}
	return key, err
}

func GenerateEd25519Key() (crypto.Signer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func LoadSytemCACertPool() *x509.CertPool {
	certPool := x509.NewCertPool()
	systemCertPool, err := x509.SystemCertPool()
	if err == nil {
		certPool = systemCertPool
	} else {
		log.Warnf("could not get system cert pool (trusted CAs). Using empty pool: %s", err)
	}

	return certPool
}

func LoadSystemCACertPoolWithExtraCAsFromFiles(casToAdd []string) *x509.CertPool {
	certPool := x509.NewCertPool()
	systemCertPool, err := x509.SystemCertPool()
	if err == nil {
		certPool = systemCertPool
	} else {
		log.Warnf("could not get system cert pool (trusted CAs). Using empty pool: %s", err)
	}

	for _, ca := range casToAdd {
		if ca == "" {
			continue
		}

		caCert, err := ReadCertificateFromFile(ca)
		if err != nil {
			log.Warnf("could not load CA certificate in %s. Skipping CA: %s", ca, err)
			continue
		}

		certPool.AddCert(caCert)
	}

	return certPool
}

func ValidateCertAndPrivKey(cert *x509.Certificate, rsaKey *rsa.PrivateKey, ecKey *ecdsa.PrivateKey) (bool, error) {
	errs := []string{
		"tls: private key type does not match public key type",
		"tls: private key does not match public key",
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if rsaKey != nil {
		keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
		_, err := tls.X509KeyPair(pemCert, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}))
		if err == nil {
			return true, nil
		}

		contains := slices.Contains(errs, err.Error())
		if contains {
			return false, nil
		}

		return false, err
	}

	if ecKey != nil {
		keyBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return false, err
		}

		_, err = tls.X509KeyPair(pemCert, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
		if err == nil {
			return true, nil
		}

		contains := slices.Contains(errs, err.Error())
		if contains {
			return false, nil
		}

		return false, err
	}

	return false, fmt.Errorf("both keys are nil")
}

func CalculateRSAKeySizes(keyMin int, KeyMax int) []int {
	var keySizes []int
	key := keyMin
	for {
		if key%128 == 0 {
			keySizes = append(keySizes, key)
			key = key + 128
		}
		if key%1024 == 0 {
			break
		}
	}
	for {
		if key%1024 == 0 {
			keySizes = append(keySizes, key)
			if key == KeyMax {
				break
			}
			key = key + 1024
		} else {
			break
		}
	}
	return keySizes
}

func CalculateECDSAKeySizes(keyMin int, KeyMax int) []int {
	var keySizes []int
	keySizes = append(keySizes, keyMin)
	if keyMin < 224 && KeyMax > 224 {
		keySizes = append(keySizes, 224)
	}
	if keyMin < 256 && KeyMax > 256 {
		keySizes = append(keySizes, 256)
	}
	if keyMin < 384 && KeyMax > 384 {
		keySizes = append(keySizes, 384)
	}
	if keyMin < 521 && KeyMax >= 521 {
		keySizes = append(keySizes, 521)
	}
	return keySizes
}

func EqualPublicKeys(pubKey1, pubKey2 any) bool {
	switch pubKey1.(type) {
	case *rsa.PublicKey:
		pk2, ok := pubKey2.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return pubKey1.(*rsa.PublicKey).Equal(pk2)
	case *ecdsa.PublicKey:
		pk2, ok := pubKey2.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return pubKey1.(*ecdsa.PublicKey).Equal(pk2)
	}

	return false
}

func ComputePublicKeyFingerprint[T *x509.Certificate | *x509.CertificateRequest](cert T) string {
	switch v := any(cert).(type) {
	case *x509.Certificate:
		return PublicKeyFingerprint(v.PublicKey)
	case *x509.CertificateRequest:
		return PublicKeyFingerprint(v.PublicKey)
	default:
		return ""
	}
}

func PublicKeyFingerprint(pubKey any) string {
	pk, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(pk))
}
