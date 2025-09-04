package x509engines

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	cmodels "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

type X509Engine struct {
	logger           *logrus.Entry
	cryptoEngine     cryptoengines.CryptoEngine
	vaDomains        []string
	softCryptoEngine *software.SoftwareCryptoEngine
}

func NewX509Engine(logger *logrus.Entry, cryptoEngine *cryptoengines.CryptoEngine, vaDomains []string) X509Engine {
	return X509Engine{
		cryptoEngine:     *cryptoEngine,
		vaDomains:        vaDomains,
		logger:           logger,
		softCryptoEngine: software.NewSoftwareCryptoEngine(logger),
	}
}

func (engine X509Engine) GetEngineConfig() cmodels.CryptoEngineInfo {
	return engine.cryptoEngine.GetEngineConfig()
}

func (engine X509Engine) GenerateKeyPair(ctx context.Context, keyMetadata cmodels.KeyMetadata) (string, crypto.Signer, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)

	if cmodels.KeyType(keyMetadata.Type) == cmodels.KeyType(x509.RSA) {
		lFunc.Debugf("requesting cryptoengine instance for RSA key generation")

		keyID, signer, err := engine.cryptoEngine.CreateRSAPrivateKey(keyMetadata.Bits)
		if err != nil {
			lFunc.Errorf("cryptoengine instance failed while generating RSA key: %s", err)
			return "", nil, err
		}
		lFunc.Debugf("cryptoengine successfully generated RSA key")
		return keyID, signer, nil
	} else {
		var curve elliptic.Curve
		switch keyMetadata.Bits {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return "", nil, errors.New("unsupported key size for ECDSA key")
		}

		lFunc.Debugf("requesting cryptoengine instance for ECDSA key generation")
		keyID, signer, err := engine.cryptoEngine.CreateECDSAPrivateKey(curve)
		if err != nil {
			lFunc.Errorf("cryptoengine instance failed while generating ECDSA key: %s", err)
			return "", nil, err
		}

		lFunc.Debugf("cryptoengine successfully generated ECDSA key")
		return keyID, signer, nil
	}
}

func (engine X509Engine) CreateRootCA(ctx context.Context, signer crypto.Signer, keyID string, subject cmodels.Subject, validity cmodels.Validity) (*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, _ := rand.Int(rand.Reader, serialNumberLimit)

	var caExpiration time.Time
	if validity.Type == cmodels.Duration {
		caExpiration = time.Now().Add(time.Duration(validity.Duration))
	} else {
		caExpiration = validity.Time
	}

	lFunc.Debugf("generated serial number for root CA: %s", helpers.SerialNumberToString(sn))
	lFunc.Debugf("validity of root CA: %s", caExpiration)
	lFunc.Debugf("key ID of root CA: %s", keyID)
	lFunc.Debugf("subject of root CA: %s", subject)

	rawHex, _ := hex.DecodeString(keyID)

	template := x509.Certificate{
		SerialNumber:          sn,
		Subject:               chelpers.SubjectToPkixName(subject),
		AuthorityKeyId:        rawHex,
		SubjectKeyId:          rawHex,
		OCSPServer:            []string{},
		CRLDistributionPoints: []string{},
		NotBefore:             time.Now(),
		NotAfter:              caExpiration,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth | x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	for _, domain := range engine.vaDomains {
		template.OCSPServer = append(template.OCSPServer, fmt.Sprintf("http://%s/ocsp", domain))
		template.CRLDistributionPoints = append(template.CRLDistributionPoints, fmt.Sprintf("http://%s/crl/%s", domain, keyID))
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, signer.Public(), signer)
	if err != nil {
		lFunc.Errorf("could not sign certificate: %s", err)
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		lFunc.Errorf("could not parse signed certificate %s", err)
		return nil, err
	}

	return certificate, nil
}

func (engine X509Engine) SignCertificateRequest(ctx context.Context, csr *x509.CertificateRequest, ca *x509.Certificate, caSigner crypto.Signer, profile cmodels.IssuanceProfile) (*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)

	// Check CSR Public Key Algorithm
	if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		if !profile.AllowRSAKeys {
			lFunc.Errorf("CSR uses RSA public key, but issuance profile does not allow RSA keys")
			return nil, fmt.Errorf("CSR uses RSA public key, but issuance profile does not allow RSA keys")
		}
	}

	if _, ok := csr.PublicKey.(*ecdsa.PublicKey); ok {
		if !profile.AllowECDSAKeys {
			lFunc.Errorf("CSR uses ECDSA public key, but issuance profile does not allow ECDSA keys")
			return nil, fmt.Errorf("CSR uses ECDSA public key, but issuance profile does not allow ECDSA keys")
		}
	}

	now := time.Now()
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, _ := rand.Int(rand.Reader, serialNumberLimit)

	var certExpiration time.Time
	if profile.Validity.Type == cmodels.Duration {
		certExpiration = now.Add(time.Duration(profile.Validity.Duration))
	} else {
		certExpiration = profile.Validity.Time
	}

	if ca.NotAfter.Before(certExpiration) {
		lFunc.Errorf("requested certificate would expire after parent CA")
		return nil, fmt.Errorf("invalid expiration")
	}

	skid, err := software.NewSoftwareCryptoEngine(engine.logger).EncodePKIXPublicKeyDigest(csr.PublicKey)
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return nil, err
	}

	rawHex, _ := hex.DecodeString(skid)

	certificateTemplate := x509.Certificate{
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SubjectKeyId:          rawHex,
		AuthorityKeyId:        ca.SubjectKeyId,
		SerialNumber:          sn,
		Issuer:                ca.Subject,
		NotBefore:             now,
		NotAfter:              certExpiration,
		OCSPServer:            []string{},
		CRLDistributionPoints: []string{},
	}

	for _, domain := range engine.vaDomains {
		certificateTemplate.OCSPServer = append(certificateTemplate.OCSPServer, fmt.Sprintf("http://%s/ocsp", domain))
		certificateTemplate.CRLDistributionPoints = append(certificateTemplate.CRLDistributionPoints, fmt.Sprintf("http://%s/crl/%s", domain, hex.EncodeToString(ca.SubjectKeyId)))
	}

	// Define certificate extra extensions
	if profile.HonorExtensions {
		exts := []pkix.Extension{}
		allowedExtOIDs := []asn1.ObjectIdentifier{
			{2, 5, 29, 17}, //SAN OID
		}

		for _, csrExt := range csr.Extensions {
			if slices.ContainsFunc(allowedExtOIDs, func(id asn1.ObjectIdentifier) bool {
				for _, allowedExt := range allowedExtOIDs {
					if allowedExt.Equal(csrExt.Id) {
						return true
					}
				}

				return false
			}) {
				exts = append(exts, csrExt)
			}
		}

		certificateTemplate.ExtraExtensions = exts
	}

	ku, extKu, err := chelpers.ExtractKeyUsageFromCSR(csr)
	if err != nil {
		lFunc.Errorf("could not extract key usage and extended key usage from CSR: %s", err)
		return nil, err
	}

	if !profile.HonorKeyUsage {
		// Use profile key usage
		certificateTemplate.KeyUsage = x509.KeyUsage(profile.KeyUsage)
	} else {
		// Use CSR key usage
		certificateTemplate.KeyUsage = ku
	}

	// Define certificate extended key usage
	var extKeyUsage []x509.ExtKeyUsage
	if !profile.HonorExtendedKeyUsages {
		// Use profile extended key usage
		for _, usage := range profile.ExtendedKeyUsages {
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsage(usage))
		}
	} else {
		extKeyUsage = extKu
	}

	certificateTemplate.ExtKeyUsage = extKeyUsage

	// Define certificate subject
	if profile.HonorSubject {
		certificateTemplate.Subject = csr.Subject
	} else {
		subject := profile.Subject
		subject.CommonName = csr.Subject.CommonName
		certificateTemplate.Subject = chelpers.SubjectToPkixName(subject)
	}

	// Check if the certificate is a CA
	if profile.SignAsCA {
		certificateTemplate.IsCA = true
		certificateTemplate.BasicConstraintsValid = true
	}

	// Sign the certificate
	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, ca, csr.PublicKey, caSigner)
	if err != nil {
		lFunc.Errorf("could not sign certificate: %s", err)
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		lFunc.Errorf("could not parse signed certificate %s", err)
		return nil, err
	}

	return certificate, nil
}

func (engine X509Engine) GenerateCertificateRequest(ctx context.Context, csrSigner crypto.Signer, subject cmodels.Subject) (*x509.CertificateRequest, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Infof("generating certificate request for subject: %s", subject)

	template := x509.CertificateRequest{
		Subject: chelpers.SubjectToPkixName(subject),
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, csrSigner)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func (engine X509Engine) GetCertificateSigner(ctx context.Context, caCertificate *x509.Certificate) (crypto.Signer, error) {
	keyID, err := engine.softCryptoEngine.EncodePKIXPublicKeyDigest(caCertificate.PublicKey)
	if err != nil {
		return nil, err
	}

	return engine.cryptoEngine.GetPrivateKeyByID(keyID)
}

func (engine X509Engine) GetDefaultCAIssuanceProfile(ctx context.Context, validity cmodels.Validity) cmodels.IssuanceProfile {
	return cmodels.IssuanceProfile{
		Validity:          validity,
		SignAsCA:          true,
		HonorExtensions:   true,
		HonorSubject:      true,
		KeyUsage:          models.X509KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
		ExtendedKeyUsages: []cmodels.X509ExtKeyUsage{},
	}
}

func (engine X509Engine) Sign(ctx context.Context, certificate *x509.Certificate, message []byte, messageType models.SignMessageType, signingAlgorithm string) ([]byte, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("starting standard signing with certificate [%s]", certificate.Subject.CommonName)

	keyID, err := engine.softCryptoEngine.EncodePKIXPublicKeyDigest(certificate.PublicKey)
	if err != nil {
		return nil, err
	}

	lFunc.Debugf("requesting signer object to crypto engine instance")
	privkey, err := engine.cryptoEngine.GetPrivateKeyByID(keyID)
	if err != nil {
		return nil, err
	}
	lFunc.Debugf("successfully retrieved certificate signer object")

	if certificate.PublicKeyAlgorithm == x509.ECDSA {
		var digest []byte
		var hashFunc crypto.Hash
		var h hash.Hash
		if signingAlgorithm == "ECDSA_SHA_256" {
			h = sha256.New()
			hashFunc = crypto.SHA256
		} else if signingAlgorithm == "ECDSA_SHA_384" {
			h = sha512.New384()
			hashFunc = crypto.SHA384
		} else if signingAlgorithm == "ECDSA_SHA_512" {
			h = sha512.New()
			hashFunc = crypto.SHA512
		} else {
			return nil, errs.ErrEngineAlgNotSupported
		}
		if messageType == models.Raw {
			h.Write(message)
			digest = h.Sum(nil)

		} else {
			digest = message
		}
		signature, err := privkey.Sign(rand.Reader, digest, hashFunc)
		if err != nil {
			return nil, err
		}
		return signature, nil
	} else if certificate.PublicKeyAlgorithm == x509.RSA {
		var digest []byte
		var hashFunc crypto.Hash
		var h hash.Hash
		if signingAlgorithm == "RSASSA_PSS_SHA_256" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_256" {
			h = sha256.New()
			hashFunc = crypto.SHA256
		} else if signingAlgorithm == "RSASSA_PSS_SHA_384" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_384" {
			h = sha512.New384()
			hashFunc = crypto.SHA384
		} else if signingAlgorithm == "RSASSA_PSS_SHA_512" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_512" {
			h = sha512.New()
			hashFunc = crypto.SHA512
		} else {
			return nil, errs.ErrEngineAlgNotSupported
		}
		if messageType == models.Raw {
			h.Write(message)
			digest = h.Sum(nil)
		} else {
			digest = message
		}

		sigAlg := strings.Split(signingAlgorithm, "_")
		if sigAlg[1] == "PSS" {
			signature, err := privkey.Sign(rand.Reader, digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashFunc,
			})
			if err != nil {
				return nil, err
			}
			return signature, nil
		} else {
			signature, err := privkey.Sign(rand.Reader, digest, hashFunc)
			if err != nil {
				return nil, err
			}
			return signature, nil
		}
	} else {
		return nil, fmt.Errorf("certificate has unsupported public key algorithm: %s", certificate.PublicKeyAlgorithm)
	}
}

func (engine X509Engine) Verify(ctx context.Context, caCertificate *x509.Certificate, signature []byte, message []byte, messageType models.SignMessageType, signingAlgorithm string) (bool, error) {
	var err error
	if caCertificate.PublicKeyAlgorithm == x509.ECDSA {
		var hasher []byte
		var h hash.Hash
		if signingAlgorithm == "ECDSA_SHA_256" {
			h = sha256.New()
		} else if signingAlgorithm == "ECDSA_SHA_384" {
			h = sha512.New384()
		} else if signingAlgorithm == "ECDSA_SHA_512" {
			h = sha512.New()
		} else {
			return false, errs.ErrEngineAlgNotSupported
		}

		if messageType == models.Raw {
			h.Write(message)
			hasher = h.Sum(nil)
		} else {
			hasher = message
		}
		pubK := caCertificate.PublicKey
		ecdsaKey, _ := pubK.(*ecdsa.PublicKey)

		return ecdsa.VerifyASN1(ecdsaKey, hasher, signature), nil
	} else if caCertificate.PublicKeyAlgorithm == x509.RSA {
		var hasher []byte
		var hashFunc crypto.Hash
		var h hash.Hash
		if signingAlgorithm == "RSASSA_PSS_SHA_256" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_256" {
			h = sha256.New()
			hashFunc = crypto.SHA256
		} else if signingAlgorithm == "RSASSA_PSS_SHA_384" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_384" {
			h = sha512.New384()
			hashFunc = crypto.SHA384
		} else if signingAlgorithm == "RSASSA_PSS_SHA_512" || signingAlgorithm == "RSASSA_PKCS1_V1_5_SHA_512" {
			h = sha512.New()
			hashFunc = crypto.SHA512
		} else {

			return false, errs.ErrEngineAlgNotSupported
		}

		if messageType == models.Raw {
			h.Write(message)
			hasher = h.Sum(nil)
		} else {
			hasher = message
		}

		pubK := caCertificate.PublicKey
		rsaKey, _ := pubK.(*rsa.PublicKey)

		sigAlg := strings.Split(signingAlgorithm, "_")
		if sigAlg[1] == "PSS" {
			err = rsa.VerifyPSS(rsaKey, hashFunc, hasher, signature, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashFunc,
			})
			if err != nil {
				return false, err
			}
			return true, nil
		} else {
			err = rsa.VerifyPKCS1v15(rsaKey, hashFunc, hasher, signature)
			if err != nil {
				return false, err
			}
			return true, nil
		}
	} else {
		return false, fmt.Errorf("CA has unsupported public key algorithm: %s", caCertificate.PublicKeyAlgorithm)
	}
}
