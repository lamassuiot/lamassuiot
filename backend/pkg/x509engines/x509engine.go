package x509engines

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

type X509Engine struct {
	logger           *logrus.Entry
	vaDomains        []string
	softCryptoEngine *software.SoftwareCryptoEngine
	kmsSDK           services.KMSService
}

func NewX509Engine(logger *logrus.Entry, vaDomains []string, kmsSDK services.KMSService) X509Engine {
	return X509Engine{
		vaDomains:        vaDomains,
		logger:           logger,
		softCryptoEngine: software.NewSoftwareCryptoEngine(logger),
		kmsSDK:           kmsSDK,
	}
}

func (engine X509Engine) CreateRootCA(ctx context.Context, signer crypto.Signer, keyID string, subject models.Subject, validity models.Validity) (*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, _ := rand.Int(rand.Reader, serialNumberLimit)

	var caExpiration time.Time
	if validity.Type == models.Duration {
		caExpiration = time.Now().Add(time.Duration(validity.Duration))
	} else {
		caExpiration = validity.Time
	}

	lFunc.Debugf("generated serial number for root CA: %s", helpers.SerialNumberToHexString(sn))
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageOCSPSigning},
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

func (engine X509Engine) SignCertificateRequest(ctx context.Context, csr *x509.CertificateRequest, ca *x509.Certificate, caSigner crypto.Signer, profile models.IssuanceProfile) (*x509.Certificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)

	// If crypto enforcement is enabled, check if the CSR public key algorithm is allowed
	if profile.CryptoEnforcement.Enabled {
		// Check CSR Public Key Algorithm
		if rsa, ok := csr.PublicKey.(*rsa.PublicKey); ok {
			if !profile.CryptoEnforcement.AllowRSAKeys {
				lFunc.Errorf("CSR uses RSA public key, but issuance profile does not allow RSA keys")
				return nil, fmt.Errorf("CSR uses RSA public key, but issuance profile does not allow RSA keys")
			} else if profile.CryptoEnforcement.AllowedRSAKeySizes != nil {
				if !slices.Contains(profile.CryptoEnforcement.AllowedRSAKeySizes, rsa.N.BitLen()) {
					lFunc.Errorf("CSR uses RSA key with size %d, but issuance profile does not allow this key size", rsa.N.BitLen())
					return nil, fmt.Errorf("CSR uses RSA key with size %d, but issuance profile does not allow this key size", rsa.N.BitLen())
				}
			}
		}

		if ecdsa, ok := csr.PublicKey.(*ecdsa.PublicKey); ok {
			if !profile.CryptoEnforcement.AllowECDSAKeys {
				lFunc.Errorf("CSR uses ECDSA public key, but issuance profile does not allow ECDSA keys")
				return nil, fmt.Errorf("CSR uses ECDSA public key, but issuance profile does not allow ECDSA keys")
			} else if profile.CryptoEnforcement.AllowedECDSAKeySizes != nil {
				if !slices.Contains(profile.CryptoEnforcement.AllowedECDSAKeySizes, ecdsa.Params().BitSize) {
					lFunc.Errorf("CSR uses ECDSA key with size %d, but issuance profile does not allow this key size", ecdsa.Params().BitSize)
					return nil, fmt.Errorf("CSR uses ECDSA key with size %d, but issuance profile does not allow this key size", ecdsa.Params().BitSize)
				}
			}
		}
	}

	now := time.Now()
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, _ := rand.Int(rand.Reader, serialNumberLimit)

	var certExpiration time.Time
	if profile.Validity.Type == models.Duration {
		certExpiration = now.Add(time.Duration(profile.Validity.Duration))
	} else {
		certExpiration = profile.Validity.Time
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

func (engine X509Engine) GenerateCertificateRequest(ctx context.Context, csrSigner crypto.Signer, subject models.Subject) (*x509.CertificateRequest, error) {
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

func (engine X509Engine) GetDefaultCAIssuanceProfile(ctx context.Context, validity models.Validity) models.IssuanceProfile {
	return models.IssuanceProfile{
		Validity:          validity,
		SignAsCA:          true,
		HonorExtensions:   true,
		HonorSubject:      true,
		KeyUsage:          models.X509KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
		ExtendedKeyUsages: []models.X509ExtKeyUsage{},
	}
}
