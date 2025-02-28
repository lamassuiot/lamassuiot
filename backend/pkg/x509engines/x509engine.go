package x509engines

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	cmodels "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

type X509Engine struct {
	logger    *logrus.Entry
	vaDomains []string
}

func NewX509Engine(logger *logrus.Entry, vaDomains []string) X509Engine {
	return X509Engine{
		vaDomains: vaDomains,
		logger:    logger,
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

	template := x509.Certificate{
		SerialNumber:          sn,
		Subject:               chelpers.SubjectToPkixName(subject),
		AuthorityKeyId:        []byte(keyID),
		SubjectKeyId:          []byte(keyID),
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
		lFunc.Errorf("requested CA would expire after parent CA")
		return nil, fmt.Errorf("invalid expiration")
	}

	keyID, err := software.NewSoftwareCryptoEngine(engine.logger).EncodePKIXPublicKeyDigest(ca.PublicKey)
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return nil, err
	}

	certificateTemplate := x509.Certificate{
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
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
		certificateTemplate.CRLDistributionPoints = append(certificateTemplate.CRLDistributionPoints, fmt.Sprintf("http://%s/crl/%s", domain, keyID))
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

	// Define certificate key usage
	certificateTemplate.KeyUsage = x509.KeyUsage(profile.KeyUsage)

	// Define certificate extended key usage
	var extKeyUsage []x509.ExtKeyUsage
	for _, usage := range profile.ExtendedKeyUsages {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsage(usage))
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
