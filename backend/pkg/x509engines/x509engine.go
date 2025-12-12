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

func (engine X509Engine) CreateRootCA(ctx context.Context, signer crypto.Signer, keyID string, subject models.Subject, validity models.Validity, profile models.IssuanceProfile) (*x509.Certificate, error) {
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

	// Build certificate template pre-populated with base CA values
	template := x509.Certificate{
		SerialNumber:          sn,
		Subject:               chelpers.SubjectToPkixName(subject),
		AuthorityKeyId:        rawHex,
		SubjectKeyId:          rawHex,
		OCSPServer:            []string{},
		CRLDistributionPoints: []string{},
		KeyUsage:              x509.KeyUsage(profile.KeyUsage),
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Pre-populate extended key usages from profile
	for _, eku := range profile.ExtendedKeyUsages {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsage(eku))
	}

	// Add OCSP and CRL distribution points
	engine.addDistributionPoints(&template, rawHex)

	// Apply issuance profile to template
	err := engine.applyIssuanceProfileToTemplate(ctx, &template, profile, time.Now())
	if err != nil {
		lFunc.Errorf("could not apply issuance profile to CA template: %s", err)
		return nil, err
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

	skid, err := software.NewSoftwareCryptoEngine(engine.logger).EncodePKIXPublicKeyDigest(csr.PublicKey)
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return nil, err
	}

	rawHex, _ := hex.DecodeString(skid)

	// Extract key usage and extended key usage from CSR
	ku, extKu, err := chelpers.ExtractKeyUsageFromCSR(csr)
	if err != nil {
		lFunc.Errorf("could not extract key usage and extended key usage from CSR: %s", err)
		return nil, err
	}

	// Build certificate template pre-populated with CSR data
	certificateTemplate := x509.Certificate{
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SubjectKeyId:          rawHex,
		AuthorityKeyId:        ca.SubjectKeyId,
		SerialNumber:          sn,
		Issuer:                ca.Subject,
		Subject:               csr.Subject,
		KeyUsage:              ku,
		ExtKeyUsage:           extKu,
		OCSPServer:            []string{},
		CRLDistributionPoints: []string{},
	}

	// Pre-populate allowed extensions from CSR
	allowedExtOIDs := []asn1.ObjectIdentifier{
		chelpers.OidExtSubjectAltName,
	}

	for _, csrExt := range csr.Extensions {
		isAllowed := false
		for _, allowedOID := range allowedExtOIDs {
			if allowedOID.Equal(csrExt.Id) {
				isAllowed = true
				break
			}
		}
		if isAllowed {
			certificateTemplate.ExtraExtensions = append(certificateTemplate.ExtraExtensions, csrExt)
		}
	}

	// Add OCSP and CRL distribution points
	engine.addDistributionPoints(&certificateTemplate, ca.SubjectKeyId)

	// Apply issuance profile to template
	err = engine.applyIssuanceProfileToTemplate(ctx, &certificateTemplate, profile, now)
	if err != nil {
		lFunc.Errorf("could not apply issuance profile to certificate template: %s", err)
		return nil, err
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

// addDistributionPoints adds OCSP and CRL distribution points to the certificate template.
// This should be called on the initial template before applying the issuance profile.
//
// Parameters:
//   - template: x509.Certificate template to modify in-place
//   - crlKeyID: key ID for CRL distribution point URLs
func (engine X509Engine) addDistributionPoints(template *x509.Certificate, crlKeyID []byte) {
	for _, domain := range engine.vaDomains {
		template.OCSPServer = append(template.OCSPServer, fmt.Sprintf("http://%s/ocsp", domain))
		template.CRLDistributionPoints = append(template.CRLDistributionPoints, fmt.Sprintf("http://%s/crl/%s", domain, hex.EncodeToString(crlKeyID)))
	}
}

// applyIssuanceProfileToTemplate applies an issuance profile to a pre-populated certificate template.
// The template should already contain base values (subject, key usages, extensions) which will be
// overridden based on the profile's Honor* flags.
//
// Parameters:
//   - template: pre-populated x509.Certificate template to modify in-place
//   - profile: the issuance profile containing all enforcement rules
//   - crlKeyID: key ID for CRL distribution point URLs
//   - now: timestamp for NotBefore
//
// Returns detailed validation errors for misconfigured profiles.
func (engine X509Engine) applyIssuanceProfileToTemplate(
	ctx context.Context,
	template *x509.Certificate,
	profile models.IssuanceProfile,
	now time.Time,
) error {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)

	// Apply validity period
	template.NotBefore = now
	if profile.Validity.Type == models.Duration {
		template.NotAfter = now.Add(time.Duration(profile.Validity.Duration))
	} else {
		template.NotAfter = profile.Validity.Time
	}

	// Apply subject - profile overrides if HonorSubject is false
	if !profile.HonorSubject {
		// Profile overrides subject but preserves CommonName from template
		originalCN := template.Subject.CommonName
		overriddenSubject := profile.Subject
		overriddenSubject.CommonName = originalCN
		template.Subject = chelpers.SubjectToPkixName(overriddenSubject)
		lFunc.Debugf("subject overridden by profile (preserving CN=%s)", originalCN)
	}

	// Apply key usage - profile overrides if HonorKeyUsage is false
	if !profile.HonorKeyUsage {
		template.KeyUsage = x509.KeyUsage(profile.KeyUsage)
		lFunc.Debugf("key usage overridden by profile: %v", template.KeyUsage)
	}

	// Apply extended key usage - profile overrides if HonorExtendedKeyUsages is false
	if !profile.HonorExtendedKeyUsages {
		var finalExtKeyUsage []x509.ExtKeyUsage
		for _, usage := range profile.ExtendedKeyUsages {
			finalExtKeyUsage = append(finalExtKeyUsage, x509.ExtKeyUsage(usage))
		}
		template.ExtKeyUsage = finalExtKeyUsage
		lFunc.Debugf("extended key usage overridden by profile: %v", template.ExtKeyUsage)
	}

	// Apply extensions - only keep allowed extensions if HonorExtensions is true
	if profile.HonorExtensions {
		// Filter to only allowed extensions
		allowedExtOIDs := []asn1.ObjectIdentifier{
			chelpers.OidExtSubjectAltName,
		}

		filteredExts := []pkix.Extension{}
		for _, ext := range template.ExtraExtensions {
			isAllowed := false
			for _, allowedOID := range allowedExtOIDs {
				if allowedOID.Equal(ext.Id) {
					isAllowed = true
					break
				}
			}
			if isAllowed {
				filteredExts = append(filteredExts, ext)
			}
		}
		template.ExtraExtensions = filteredExts
		lFunc.Debugf("extensions filtered to allowed OIDs, kept %d extensions", len(filteredExts))
	} else {
		// Don't honor extensions - clear them
		template.ExtraExtensions = nil
		lFunc.Debugf("extensions cleared (HonorExtensions=false)")
	}

	// Apply CA constraints
	if profile.SignAsCA {
		template.IsCA = true
		template.BasicConstraintsValid = true
		lFunc.Debugf("CA constraints applied (IsCA=true)")
	}

	return nil
}
