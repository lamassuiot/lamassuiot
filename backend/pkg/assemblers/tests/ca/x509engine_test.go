package ca

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	beservice "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/x509engines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func setupX509TestSuite(t *testing.T) (services.KMSService, *x509engines.X509Engine, error) {
	builder := tests.TestServiceBuilder{}.WithDatabase("kms", "ca")
	testServer, err := builder.Build(t)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create Device Manager test server: %s", err)
	}

	err = testServer.BeforeEach()
	if err != nil {
		t.Fatalf("could not run 'BeforeEach' cleanup func in test case: %s", err)
	}

	// Create a new instance of GoCryptoEngine
	log := chelpers.SetupLogger(config.Info, "Test Case", "Golang Engine")

	x509Engine := x509engines.NewX509Engine(log, []string{"ocsp.lamassu.io", "va.lamassu.io"}, testServer.KMS.HttpKMSSDK)
	return testServer.KMS.HttpKMSSDK, &x509Engine, nil
}

func checkCertificate(cert *x509.Certificate, tcSubject models.Subject, tcKeyMetadata models.KeyType, tcExpirationTime time.Time) error {
	if cert.Subject.CommonName != tcSubject.CommonName {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.CommonName, tcSubject.CommonName)
	}

	if cert.Subject.Organization[0] != tcSubject.Organization {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.Organization, tcSubject.Organization)
	}

	if cert.Subject.OrganizationalUnit[0] != tcSubject.OrganizationUnit {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.OrganizationalUnit, tcSubject.OrganizationUnit)
	}

	if cert.Subject.Country[0] != tcSubject.Country {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.Country, tcSubject.Country)
	}

	if cert.Subject.Province[0] != tcSubject.State {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.Province, tcSubject.State)
	}

	if cert.Subject.Locality[0] != tcSubject.Locality {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.Locality, tcSubject.Locality)
	}

	if models.KeyType(cert.PublicKeyAlgorithm) != tcKeyMetadata {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.PublicKeyAlgorithm, tcKeyMetadata)
	}

	if !cert.NotAfter.Equal(tcExpirationTime.UTC().Truncate(time.Second)) {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.NotAfter, tcExpirationTime.UTC().Truncate(time.Minute))
	}

	if cert.OCSPServer[0] != "http://ocsp.lamassu.io/ocsp" {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.OCSPServer[0], "http://ocsp.lamassu.io/ocsp")
	}

	if cert.OCSPServer[1] != "http://va.lamassu.io/ocsp" {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.OCSPServer[1], "http://va.lamassu.io/ocsp")
	}

	v2CrlID := hex.EncodeToString(cert.AuthorityKeyId)
	if cert.CRLDistributionPoints[0] != "http://ocsp.lamassu.io/crl/"+v2CrlID {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.CRLDistributionPoints[0], "http://crl.lamassu.io/crl/"+v2CrlID)
	}

	if cert.CRLDistributionPoints[1] != "http://va.lamassu.io/crl/"+v2CrlID {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.CRLDistributionPoints[1], "http://va.lamassu.io/crl/"+v2CrlID)
	}
	return nil
}

func checkCACertificate(cert *x509.Certificate, ca *x509.Certificate, tcSubject models.Subject, tcKeyMetadata models.KeyMetadata, tcExpirationTime time.Time) error {
	err := checkCertificate(cert, tcSubject, tcKeyMetadata.Type, tcExpirationTime)
	if err != nil {
		return err
	}

	if cert.IsCA != true {
		return fmt.Errorf("unexpected result, got: %t, want: %t", cert.IsCA, true)
	}

	if cert.OCSPServer[0] != "http://ocsp.lamassu.io/ocsp" {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.OCSPServer[0], "http://ocsp.lamassu.io/ocsp")
	}

	if cert.OCSPServer[1] != "http://va.lamassu.io/ocsp" {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.OCSPServer[1], "http://va.lamassu.io/ocsp")
	}

	v2CrlID := hex.EncodeToString(ca.SubjectKeyId)
	if cert.CRLDistributionPoints[0] != "http://ocsp.lamassu.io/crl/"+v2CrlID {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.CRLDistributionPoints[0], "http://crl.lamassu.io/crl/"+v2CrlID)
	}

	if cert.CRLDistributionPoints[1] != "http://va.lamassu.io/crl/"+v2CrlID {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.CRLDistributionPoints[1], "http://va.lamassu.io/crl/"+v2CrlID)
	}

	return nil
}



func TestCreateRootCA(t *testing.T) {
	kms, x509Engine, err := setupX509TestSuite(t)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}

	expirationTime := time.Now().AddDate(1, 0, 0) // Set expiration time to 1 year from now

	checkOk := func(cert *x509.Certificate, tcSubject models.Subject, tcKeyMetadata models.KeyMetadata, tcExpirationTime time.Time, err error) error {
		if err != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}

		return checkCACertificate(cert, cert, tcSubject, tcKeyMetadata, tcExpirationTime)
	}

	caSubject := models.Subject{
		CommonName:       "Root CA",
		Organization:     "Lamassu IoT",
		OrganizationUnit: "CA",
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
	}

	var testcases = []struct {
		name           string
		caId           string
		subject        models.Subject
		keyMetadata    models.KeyMetadata
		expirationTime time.Time
		check          func(cert *x509.Certificate, tcSubject models.Subject, tcKeyMetadata models.KeyMetadata, expirationTime time.Time, err error) error
	}{
		{
			name:    "OK/RSA_2048",
			caId:    "rootCA-RSA2048",
			subject: caSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name:    "OK/ECDSA_256",
			caId:    "rootCA-ECDSA_256",
			subject: caSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name:    "OK/MLDSA_44",
			caId:    "rootCA-MLDSA_44",
			subject: caSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.MLDSA,
				Bits: 44,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name:    "OK/Ed25519",
			caId:    "rootCA-Ed25519",
			subject: caSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.Ed25519),
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			key, err := kms.CreateKey(ctx, services.CreateKeyInput{
				Algorithm: tc.keyMetadata.Type.String(),
				Size:      tc.keyMetadata.Bits,
				Name:      tc.caId,
			})
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			caSigner := beservice.NewKMSCryptoSigner(ctx, *key, kms)

			cert, err := x509Engine.CreateRootCA(ctx, caSigner, key.KeyID, tc.subject, models.Validity{
				Type: models.Time,
				Time: tc.expirationTime,
			}, x509Engine.GetDefaultCAIssuanceProfile(ctx, models.Validity{
				Type: models.Time,
				Time: tc.expirationTime,
			}))
			err = tc.check(cert, tc.subject, tc.keyMetadata, tc.expirationTime, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestRootCAExtendedKeyUsage(t *testing.T) {
	kms, x509Engine, err := setupX509TestSuite(t)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}

	caSubject := models.Subject{
		CommonName:       "Root CA EKU Test",
		Organization:     "Lamassu IoT",
		OrganizationUnit: "CA",
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
	}

	expirationTime := time.Now().AddDate(1, 0, 0)

	var testcases = []struct {
		name           string
		caId           string
		subject        models.Subject
		keyMetadata    models.KeyMetadata
		expirationTime time.Time
		expectedEKUs   []x509.ExtKeyUsage
	}{
		{
			name:    "RootCA_RSA_2048_EKU",
			caId:    "rootCA-EKU-RSA2048",
			subject: caSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			expectedEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageOCSPSigning},
		},
		{
			name:    "RootCA_ECDSA_256_EKU",
			caId:    "rootCA-EKU-ECDSA256",
			subject: caSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			expectedEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageOCSPSigning},
		},
		{
			name:    "RootCA_No_EKU",
			caId:    "rootCA-EKU-None",
			subject: caSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			expectedEKUs:   []x509.ExtKeyUsage{},
		},
		{
			name:    "RootCA_Single_EKU_ClientAuth",
			caId:    "rootCA-EKU-ClientAuth",
			subject: caSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			expectedEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:    "RootCA_Multiple_EKU_Mixed",
			caId:    "rootCA-EKU-Mixed",
			subject: caSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 4096,
			},
			expirationTime: expirationTime,
			expectedEKUs: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageCodeSigning,
				x509.ExtKeyUsageEmailProtection,
			},
		},
		{
			name:    "RootCA_ECDSA_384_TimeStamping",
			caId:    "rootCA-EKU-TimeStamping",
			subject: caSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 384,
			},
			expirationTime: expirationTime,
			expectedEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		},
		{
			name:    "RootCA_CodeSigning_Only",
			caId:    "rootCA-EKU-CodeSign",
			subject: caSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 3072,
			},
			expirationTime: expirationTime,
			expectedEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			key, err := kms.CreateKey(ctx, services.CreateKeyInput{
				Algorithm: tc.keyMetadata.Type.String(),
				Size:      tc.keyMetadata.Bits,
				Name:      tc.caId,
			})
			if err != nil {
				t.Fatalf("unexpected error creating key: %s", err)
			}

			caSigner := beservice.NewKMSCryptoSigner(ctx, *key, kms)

			// Create profile with Extended Key Usages based on test case
			profile := models.IssuanceProfile{
				Validity: models.Validity{
					Type: models.Time,
					Time: tc.expirationTime,
				},
				SignAsCA: true,
				KeyUsage: models.X509KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
			}

			// Convert test case expected EKUs to profile EKUs
			for _, eku := range tc.expectedEKUs {
				profile.ExtendedKeyUsages = append(profile.ExtendedKeyUsages, models.X509ExtKeyUsage(eku))
			}

			cert, err := x509Engine.CreateRootCA(ctx, caSigner, key.KeyID, tc.subject, models.Validity{
				Type: models.Time,
				Time: tc.expirationTime,
			}, profile)
			if err != nil {
				t.Fatalf("unexpected error creating root CA: %s", err)
			}

			// Verify certificate is a CA
			if !cert.IsCA {
				t.Errorf("certificate is not marked as CA")
			}

			// Verify Extended Key Usage
			if len(cert.ExtKeyUsage) != len(tc.expectedEKUs) {
				t.Errorf("ExtKeyUsage count mismatch: got %d, want %d", len(cert.ExtKeyUsage), len(tc.expectedEKUs))
			}

			for _, expectedEKU := range tc.expectedEKUs {
				if !slices.Contains(cert.ExtKeyUsage, expectedEKU) {
					t.Errorf("Missing expected EKU: %v. Certificate has EKUs: %v", expectedEKU, cert.ExtKeyUsage)
				}
			}

			// Verify each EKU in the certificate is expected
			for _, certEKU := range cert.ExtKeyUsage {
				if !slices.Contains(tc.expectedEKUs, certEKU) {
					t.Errorf("Unexpected EKU in certificate: %v. Expected EKUs: %v", certEKU, tc.expectedEKUs)
				}
			}

			// Verify Key Usage includes CertSign for CA
			expectedKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
			if cert.KeyUsage != expectedKeyUsage {
				t.Errorf("KeyUsage mismatch: got %d, want %d", cert.KeyUsage, expectedKeyUsage)
			}
		})
	}
}

func TestCreateSubordinateCA(t *testing.T) {
	// Setup
	kmsSvc, x509Engine, err := setupX509TestSuite(t)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}

	subject := models.Subject{
		CommonName:       "Root CA",
		Organization:     "Lamassu IoT",
		OrganizationUnit: "CA",
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
	}

	caExpirationTime := time.Now().AddDate(2, 0, 0) // Set expiration time to 2 years from now
	expirationTime := time.Now().AddDate(1, 0, 0)   // Set expiration time to 1 year from now

	ctx := context.Background()

	// Create RSA Root CA
	keyRSA, err := kmsSvc.CreateKey(context.Background(), services.CreateKeyInput{
		Algorithm: "RSA",
		Size:      2048,
		Name:      "rootCA-RSA",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerRSA := beservice.NewKMSCryptoSigner(ctx, *keyRSA, kmsSvc)
	rootCaCertRSA, err := x509Engine.CreateRootCA(ctx, caSignerRSA, keyRSA.KeyID, subject, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	}, x509Engine.GetDefaultCAIssuanceProfile(ctx, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	}))
	if err != nil {
		t.Fatalf("unexpected result in test case: %s", err)
	}

	// Create ECDSA Root CA
	keyEC, err := kmsSvc.CreateKey(context.Background(), services.CreateKeyInput{
		Algorithm: "ECDSA",
		Size:      256,
		Name:      "rootCA-EC",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerEC := beservice.NewKMSCryptoSigner(ctx, *keyEC, kmsSvc)
	rootCaCertEC, err := x509Engine.CreateRootCA(ctx, caSignerEC, keyEC.KeyID, subject, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	}, x509Engine.GetDefaultCAIssuanceProfile(ctx, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	}))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Create MLDSA Root CA
	keyMLDSA, err := kmsSvc.CreateKey(context.Background(), services.CreateKeyInput{
		Algorithm: "ML-DSA",
		Size:      65,
		Name:      "rootCA-MLDSA",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerMLDSA := beservice.NewKMSCryptoSigner(ctx, *keyMLDSA, kmsSvc)
	rootCaCertMLDSA, err := x509Engine.CreateRootCA(ctx, caSignerMLDSA, keyMLDSA.KeyID, subject, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	}, x509Engine.GetDefaultCAIssuanceProfile(ctx, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	}))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Create Ed25519 Root CA
	keyEd25519Sub, err := kmsSvc.CreateKey(context.Background(), services.CreateKeyInput{
		Algorithm: "Ed25519",
		Size:      0,
		Name:      "rootCA-Ed25519",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerEd25519Sub := beservice.NewKMSCryptoSigner(ctx, *keyEd25519Sub, kmsSvc)
	rootCaCertEd25519, err := x509Engine.CreateRootCA(ctx, caSignerEd25519Sub, keyEd25519Sub.KeyID, subject, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	}, x509Engine.GetDefaultCAIssuanceProfile(ctx, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	}))
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	subordinateSubject := models.Subject{
		CommonName:       "Subordinate CA",
		Organization:     "Lamassu IoT",
		OrganizationUnit: "CA",
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
	}

	checkOk := func(cert *x509.Certificate, ca *x509.Certificate, tcSubject models.Subject, tcKeyMetadata models.KeyMetadata, tcExpirationTime time.Time, err error) error {
		// Verify the result
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		return checkCACertificate(cert, ca, tcSubject, tcKeyMetadata, tcExpirationTime)
	}

	var testcases = []struct {
		name            string
		subordinateCAID string
		rootCaCert      *x509.Certificate
		parentCASigner  crypto.Signer
		subject         models.Subject
		keyMetadata     models.KeyMetadata
		expirationTime  time.Time
		check           func(cert *x509.Certificate, ca *x509.Certificate, tcSubject models.Subject, tcKeyMetadata models.KeyMetadata, tcExpirationTime time.Time, err error) error
	}{
		{name: "OK/RSA_RSA",
			subordinateCAID: "subCA-RSA-RSA",
			rootCaCert:      rootCaCertRSA,
			parentCASigner:  caSignerRSA,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/RSA_EC",
			subordinateCAID: "subCA-RSA-EC",
			rootCaCert:      rootCaCertRSA,
			parentCASigner:  caSignerRSA,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/RSA_MLDSA",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertRSA,
			parentCASigner:  caSignerRSA,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.MLDSA,
				Bits: 44,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/RSA_Ed25519",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertRSA,
			parentCASigner:  caSignerRSA,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.Ed25519),
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/EC_RSA",
			subordinateCAID: "subCA-EC-RSA",
			rootCaCert:      rootCaCertEC,
			parentCASigner:  caSignerEC,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/EC_EC",
			subordinateCAID: "subCA-EC-EC",
			rootCaCert:      rootCaCertEC,
			parentCASigner:  caSignerEC,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/EC_MLDSA",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertEC,
			parentCASigner:  caSignerEC,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.MLDSA,
				Bits: 65,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/EC_Ed25519",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertEC,
			parentCASigner:  caSignerEC,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.Ed25519),
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/MLDSA_RSA",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertMLDSA,
			parentCASigner:  caSignerMLDSA,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/MLDSA_EC",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertMLDSA,
			parentCASigner:  caSignerMLDSA,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/MLDSA_MLDSA",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertMLDSA,
			parentCASigner:  caSignerMLDSA,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.MLDSA,
				Bits: 87,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/MLDSA_Ed25519",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertMLDSA,
			parentCASigner:  caSignerMLDSA,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.Ed25519),
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/Ed25519_RSA",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertEd25519,
			parentCASigner:  caSignerEd25519Sub,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/Ed25519_EC",
			subordinateCAID: "subCA",
    // ... 1154 lines omitted
	}
    // ... 1153 lines omitted
			}
    // ... 1152 lines omitted
			}
    // ... 1151 lines omitted
			}
    // ... 1150 lines omitted
			}
    // ... 1149 lines omitted
	}
}
    // ... 1147 lines omitted
func TestSignCertificateRequest(t *testing.T) {
    // ... 1146 lines omitted
	}
    // ... 1145 lines omitted
	}
    // ... 1144 lines omitted
	}
    // ... 1143 lines omitted
	}
    // ... 1142 lines omitted
	}
    // ... 1141 lines omitted
	}
    // ... 1140 lines omitted
	}
    // ... 1139 lines omitted
	}
    // ... 1138 lines omitted
	}
    // ... 1137 lines omitted
	}
    // ... 1136 lines omitted
	}
    // ... 1135 lines omitted
	}
    // ... 1134 lines omitted
		}
    // ... 1133 lines omitted
		}
    // ... 1132 lines omitted
		}
    // ... 1131 lines omitted
		}
    // ... 1130 lines omitted
	}
    // ... 1129 lines omitted
		}
    // ... 1128 lines omitted
		}
    // ... 1127 lines omitted
	}
    // ... 1126 lines omitted
	}
    // ... 1125 lines omitted
		{
    // ... 1124 lines omitted
		{
    // ... 1123 lines omitted
		{
    // ... 1122 lines omitted
		{
    // ... 1121 lines omitted
		{
    // ... 1120 lines omitted
		{
    // ... 1119 lines omitted
		{
    // ... 1118 lines omitted
		{
    // ... 1117 lines omitted
		{
    // ... 1116 lines omitted
		{
    // ... 1115 lines omitted
		{
    // ... 1114 lines omitted
		{
    // ... 1113 lines omitted
		{
    // ... 1112 lines omitted
		{
    // ... 1111 lines omitted
		{
    // ... 1110 lines omitted
		{
    // ... 1109 lines omitted
		{
    // ... 1108 lines omitted
				}
    // ... 1107 lines omitted
				}
    // ... 1106 lines omitted
				}
    // ... 1105 lines omitted
				}
    // ... 1104 lines omitted
				}
    // ... 1103 lines omitted
		{
    // ... 1102 lines omitted
				}
    // ... 1101 lines omitted
				}
    // ... 1100 lines omitted
				}
    // ... 1099 lines omitted
				}
    // ... 1098 lines omitted
				}
    // ... 1097 lines omitted
		{
    // ... 1096 lines omitted
				}
    // ... 1095 lines omitted
					}
				}
    // ... 1093 lines omitted
		{
    // ... 1092 lines omitted
				}
    // ... 1091 lines omitted
				}
    // ... 1090 lines omitted
		{
    // ... 1089 lines omitted
				}
    // ... 1088 lines omitted
				}
    // ... 1087 lines omitted
		{
    // ... 1086 lines omitted
	}
    // ... 1085 lines omitted
			}
    // ... 1084 lines omitted
	}
}
    // ... 1082 lines omitted
func TestChameleonCertificateRequest(t *testing.T) {
    // ... 1081 lines omitted
	}
    // ... 1080 lines omitted
	}
    // ... 1079 lines omitted
	}
    // ... 1078 lines omitted
	}
    // ... 1077 lines omitted
	}
    // ... 1076 lines omitted
	}
    // ... 1075 lines omitted
	}
    // ... 1074 lines omitted
	}
    // ... 1073 lines omitted
	}
    // ... 1072 lines omitted
	}
    // ... 1071 lines omitted
	}
    // ... 1070 lines omitted
	}
    // ... 1069 lines omitted
	}
    // ... 1068 lines omitted
	}
    // ... 1067 lines omitted
	}
    // ... 1066 lines omitted
	}
    // ... 1065 lines omitted
		}
    // ... 1064 lines omitted
		}
    // ... 1063 lines omitted
		}
    // ... 1062 lines omitted
		}
    // ... 1061 lines omitted
		}
    // ... 1060 lines omitted
		}
    // ... 1059 lines omitted
	}
    // ... 1058 lines omitted
		}
    // ... 1057 lines omitted
		}
    // ... 1056 lines omitted
		}
    // ... 1055 lines omitted
	}
    // ... 1054 lines omitted
	}
    // ... 1053 lines omitted
		{
    // ... 1052 lines omitted
		{
    // ... 1051 lines omitted
		{
    // ... 1050 lines omitted
		{
    // ... 1049 lines omitted
				}
    // ... 1048 lines omitted
				}
    // ... 1047 lines omitted
				}
    // ... 1046 lines omitted
				}
    // ... 1045 lines omitted
				}
    // ... 1044 lines omitted
		{
    // ... 1043 lines omitted
				}
    // ... 1042 lines omitted
				}
    // ... 1041 lines omitted
				}
    // ... 1040 lines omitted
				}
    // ... 1039 lines omitted
				}
    // ... 1038 lines omitted
		{
    // ... 1037 lines omitted
				}
    // ... 1036 lines omitted
					}
				}
    // ... 1034 lines omitted
				}
    // ... 1033 lines omitted
					}
				}
    // ... 1031 lines omitted
		{
    // ... 1030 lines omitted
	}
    // ... 1029 lines omitted
			}
    // ... 1028 lines omitted
	}
}
    // ... 1026 lines omitted
func TestGetEngineConfig(t *testing.T) {
    // ... 1025 lines omitted
	}
}
// ... 1023 more lines (total: 1859)