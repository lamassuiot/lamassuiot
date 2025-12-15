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
				Type: models.KeyType(x509.MLDSA),
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
				Bits: 256,
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
			})
			err = tc.check(cert, tc.subject, tc.keyMetadata, tc.expirationTime, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestCreateChameleonRootCA(t *testing.T) {
	kmsSvc, x509Engine, err := setupX509TestSuite(t)
	if err != nil {
		t.Fatalf("setuf failed: %s", err)
	}

	expirationTime := time.Now().AddDate(1, 0, 0) // Set expiration time to 1 year from now

	checkOk := func(cert *x509.Certificate, tcSubject models.Subject, tcDeltaKeyMetadata, tcBaseKeyMetadata models.KeyMetadata, tcExpirationTime time.Time, err error) error {
		if err != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}

		// Check Root CA Certificate
		err = checkCACertificate(cert, cert, tcSubject, tcBaseKeyMetadata, tcExpirationTime)
		if err != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}

		// Check Delta CA Certificate
		deltaCert, err := x509.ReconstructDeltaCertificate(cert)
		if err != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}

		return checkCACertificate(deltaCert, deltaCert, tcSubject, tcDeltaKeyMetadata, tcExpirationTime)
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
		name             string
		caId             string
		subject          models.Subject
		baseKeyMetadata  models.KeyMetadata
		deltaKeyMetadata models.KeyMetadata
		expirationTime   time.Time
		check            func(cert *x509.Certificate, tcSubject models.Subject, tcDeltaKeyMetadata, tcBaseKeyMetadata models.KeyMetadata, tcExpirationTime time.Time, err error) error
	}{
		{
			name:    "OK/RSA_2048-MLDSA",
			caId:    "rootCA-PQ-Chameleon-RSA2048-MLDSA",
			subject: caSubject,
			baseKeyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			deltaKeyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.MLDSA),
				Bits: 65,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name:    "OK/Ed25519-MLDSA",
			caId:    "rootCA-PQ-Chameleon-Ed25519-MLDSA",
			subject: caSubject,
			baseKeyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.Ed25519),
				Bits: 256,
			},
			deltaKeyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.MLDSA),
				Bits: 65,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name:    "OK/ECDSA_256-MLDSA",
			caId:    "rootCA-PQ-Chameleon-ECDSA_256-MLDSA",
			subject: caSubject,
			baseKeyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			deltaKeyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.MLDSA),
				Bits: 65,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			baseKey, err := kmsSvc.CreateKey(ctx, services.CreateKeyInput{
				Algorithm: tc.baseKeyMetadata.Type.String(),
				Size:      tc.baseKeyMetadata.Bits,
				Name:      tc.caId,
			})
			baseCaSigner := beservice.NewKMSCryptoSigner(ctx, *baseKey, kmsSvc)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			deltaKey, err := kmsSvc.CreateKey(ctx, services.CreateKeyInput{
				Algorithm: tc.deltaKeyMetadata.Type.String(),
				Size:      tc.deltaKeyMetadata.Bits,
				Name:      tc.caId,
			})
			deltaCaSigner := beservice.NewKMSCryptoSigner(ctx, *deltaKey, kmsSvc)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			cert, err := x509Engine.CreateChameleonRootCA(ctx, deltaCaSigner, baseCaSigner, deltaKey.KeyID, baseKey.KeyID, tc.subject, models.Validity{
				Type: models.Time,
				Time: tc.expirationTime,
			})
			if err != nil {
				t.Fatalf("unexpected creating the ca: %s", err)
			}

			err = tc.check(cert, tc.subject, tc.deltaKeyMetadata, tc.baseKeyMetadata, tc.expirationTime, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
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
	})
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
	})
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
	})
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Create Ed25519 Root CA
	keyEd25519, err := kmsSvc.CreateKey(context.Background(), services.CreateKeyInput{
		Algorithm: "Ed25519",
		Size:      256,
		Name:      "rootCA-Ed25519",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerEd25519 := beservice.NewKMSCryptoSigner(ctx, *keyEd25519, kmsSvc)
	rootCaCertEd25519, err := x509Engine.CreateRootCA(ctx, caSignerEd25519, keyEd25519.KeyID, subject, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	})
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
				Type: models.KeyType(x509.MLDSA),
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
				Bits: 256,
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
				Type: models.KeyType(x509.MLDSA),
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
				Bits: 256,
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
				Type: models.KeyType(x509.MLDSA),
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
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/Ed25519_RSA",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertEd25519,
			parentCASigner:  caSignerEd25519,
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
			rootCaCert:      rootCaCertEd25519,
			parentCASigner:  caSignerEd25519,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/Ed25519_MLDSA",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertEd25519,
			parentCASigner:  caSignerEd25519,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.MLDSA),
				Bits: 87,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/Ed25519_Ed25519",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertEd25519,
			parentCASigner:  caSignerEd25519,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.Ed25519),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// Create subordinate CA key using KMS
			subCAKey, err := kmsSvc.CreateKey(context.Background(), services.CreateKeyInput{
				Algorithm: tc.keyMetadata.Type.String(),
				Size:      tc.keyMetadata.Bits,
				Name:      tc.subordinateCAID,
			})
			if err != nil {
				t.Fatalf("unexpected error in key gen: %s", err)
			}
			subCASigner := beservice.NewKMSCryptoSigner(ctx, *subCAKey, kmsSvc)

			subCACSR, err := x509Engine.GenerateCertificateRequest(ctx, subCASigner, tc.subject)
			if err != nil {
				t.Fatalf("unexpected error in csr gen: %s", err)
			}

			cert, err := x509Engine.SignCertificateRequest(ctx, subCACSR, tc.rootCaCert, tc.parentCASigner, x509Engine.GetDefaultCAIssuanceProfile(ctx, models.Validity{
				Type: models.Time,
				Time: tc.expirationTime,
			}))
			if err != nil {
				t.Fatalf("unexpected error in sign cert: %s", err)
			}

			// Call the CreateSubordinateCA method
			err = tc.check(cert, tc.rootCaCert, tc.subject, tc.keyMetadata, tc.expirationTime, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})

	}
}

func TestSignCertificateRequest(t *testing.T) {
	kmsSvc, x509Engine, err := setupX509TestSuite(t)
	if err != nil {
		t.Fatalf("setup failed: %s", err)
	}

	subject := models.Subject{
		CommonName: "Root CA",
	}

	caExpirationTime := time.Now().AddDate(2, 0, 0) // Set expiration time to 2 year from now
	expirationTime := time.Now().AddDate(1, 0, 0)   // Set expiration time to 1 year from now

	ctx := context.Background()

	// Create RSA CA key
	keyRSA, err := kmsSvc.CreateKey(context.Background(), services.CreateKeyInput{
		Algorithm: "RSA",
		Size:      2048,
		Name:      "signCertReq-RSA",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerRSA := beservice.NewKMSCryptoSigner(ctx, *keyRSA, kmsSvc)

	caCertificateRSA, err := x509Engine.CreateRootCA(ctx, caSignerRSA, keyRSA.KeyID, subject, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	})
	if err != nil {
		t.Fatalf("unexpected result in test case: %s", err)
	}

	// Create ECDSA CA key
	keyEC, err := kmsSvc.CreateKey(context.Background(), services.CreateKeyInput{
		Algorithm: "ECDSA",
		Size:      256,
		Name:      "signCertReq-EC",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerEC := beservice.NewKMSCryptoSigner(ctx, *keyEC, kmsSvc)

	caCertificateEC, err := x509Engine.CreateRootCA(ctx, caSignerEC, keyEC.KeyID, subject, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	})
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Create MLDSA CA key
	keyMLDSA, err := kmsSvc.CreateKey(context.Background(), services.CreateKeyInput{
		Algorithm: "ML-DSA",
		Size:      65,
		Name:      "signCertReq-MLDSA",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerMLDSA := beservice.NewKMSCryptoSigner(ctx, *keyMLDSA, kmsSvc)

	caCertificateMLDSA, err := x509Engine.CreateRootCA(ctx, caSignerMLDSA, keyMLDSA.KeyID, subject, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	})
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Create Ed25519 CA key
	keyEd25519, err := kmsSvc.CreateKey(context.Background(), services.CreateKeyInput{
		Algorithm: "Ed25519",
		Size:      256,
		Name:      "signCertReq-Ed25519",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerEd25519 := beservice.NewKMSCryptoSigner(ctx, *keyEd25519, kmsSvc)

	caCertificateEd25519, err := x509Engine.CreateRootCA(ctx, caSignerEd25519, keyEd25519.KeyID, subject, models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	})
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	caCertificateNotImported, _, err := chelpers.GenerateSelfSignedCA(x509.ECDSA, 365*24*time.Hour, "MyCA")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	csrSubject := models.Subject{
		CommonName:       "Subordinate CA",
		Organization:     "Lamassu IoT",
		OrganizationUnit: "CA",
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
	}

	checkOk := func(cert *x509.Certificate, tcSubject models.Subject, keyType models.KeyType, expirationTime time.Time, errCsr error, errSign error) error {
		if errCsr != nil {
			return fmt.Errorf("unexpected error in csr gen: %s", errCsr)
		}

		if errSign != nil {
			return fmt.Errorf("unexpected error in signature: %s", errSign)
		}

		err := checkCertificate(cert, tcSubject, keyType, expirationTime)
		if err != nil {
			return err
		}

		if cert.Subject.CommonName != tcSubject.CommonName {
			return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.CommonName, tcSubject.CommonName)
		}

		return nil
	}

	checkFail := func(cert *x509.Certificate, tcSubject models.Subject, keyType models.KeyType, expirationTime time.Time, errCsr error, errSign error) error {
		if errCsr != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}
		if errSign == nil {
			return fmt.Errorf("expected error, got nil")
		}

		return nil
	}

	certProfile := models.IssuanceProfile{
		Validity: models.Validity{
			Type: models.Time,
			Time: expirationTime,
		},
		SignAsCA:     false,
		HonorSubject: true,
		KeyUsage:     models.X509KeyUsage(x509.KeyUsageKeyAgreement),
		ExtendedKeyUsages: []models.X509ExtKeyUsage{
			models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
		},
		HonorExtensions: true,
	}

	var testcases = []struct {
		name          string
		caCertificate *x509.Certificate
		caSigner      crypto.Signer
		profile       models.IssuanceProfile
		subject       models.Subject
		extensions    func() []pkix.Extension
		keyType       models.KeyType
		key           func() any
		check         func(cert *x509.Certificate, tcSubject models.Subject, keyType models.KeyType, expirationTime time.Time, errCsr error, errSign error) error
	}{
		{
			name:          "OK/RSA_RSA",
			caCertificate: caCertificateRSA,
			caSigner:      caSignerRSA,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.RSA),
			key: func() any {
				key, _ := chelpers.GenerateRSAKey(2048)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EC_RSA",
			caCertificate: caCertificateEC,
			subject:       csrSubject,
			caSigner:      caSignerEC,
			profile:       certProfile,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.RSA),
			key: func() any {
				key, _ := chelpers.GenerateRSAKey(2048)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/MLDSA_RSA",
			caCertificate: caCertificateMLDSA,
			subject:       csrSubject,
			caSigner:      caSignerMLDSA,
			profile:       certProfile,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.RSA),
			key: func() any {
				key, _ := chelpers.GenerateRSAKey(2048)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/Ed25519_RSA",
			caCertificate: caCertificateEd25519,
			subject:       csrSubject,
			caSigner:      caSignerEd25519,
			profile:       certProfile,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.RSA),
			key: func() any {
				key, _ := chelpers.GenerateRSAKey(2048)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/RSA_EC",
			caCertificate: caCertificateRSA,
			caSigner:      caSignerRSA,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.ECDSA),
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EC_EC",
			caCertificate: caCertificateEC,
			caSigner:      caSignerEC,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.ECDSA),
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/MLDSA_EC",
			caCertificate: caCertificateMLDSA,
			caSigner:      caSignerMLDSA,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.ECDSA),
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/Ed25519_EC",
			caCertificate: caCertificateEd25519,
			caSigner:      caSignerEd25519,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.ECDSA),
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/RSA_MLDSA",
			caCertificate: caCertificateRSA,
			caSigner:      caSignerRSA,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.MLDSA),
			key: func() any {
				key, _ := chelpers.GenerateMLDSAKey(65)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EC_MLDSA",
			caCertificate: caCertificateEC,
			caSigner:      caSignerEC,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.MLDSA),
			key: func() any {
				key, _ := chelpers.GenerateMLDSAKey(65)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/MLDSA_MLDSA",
			caCertificate: caCertificateMLDSA,
			caSigner:      caSignerMLDSA,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.MLDSA),
			key: func() any {
				key, _ := chelpers.GenerateMLDSAKey(65)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/Ed25519_MLDSA",
			caCertificate: caCertificateEd25519,
			caSigner:      caSignerEd25519,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.MLDSA),
			key: func() any {
				key, _ := chelpers.GenerateMLDSAKey(65)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/RSA_Ed25519",
			caCertificate: caCertificateRSA,
			caSigner:      caSignerRSA,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.Ed25519),
			key: func() any {
				key, _ := chelpers.GenerateEd25519Key()
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EC_Ed25519",
			caCertificate: caCertificateEC,
			caSigner:      caSignerEC,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.Ed25519),
			key: func() any {
				key, _ := chelpers.GenerateEd25519Key()
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/MLDSA_Ed25519",
			caCertificate: caCertificateMLDSA,
			caSigner:      caSignerMLDSA,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.Ed25519),
			key: func() any {
				key, _ := chelpers.GenerateEd25519Key()
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/Ed25519_Ed25519",
			caCertificate: caCertificateEd25519,
			caSigner:      caSignerEd25519,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       models.KeyType(x509.Ed25519),
			key: func() any {
				key, _ := chelpers.GenerateEd25519Key()
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EXT_SAN",
			caCertificate: caCertificateEC,
			caSigner:      caSignerEC,
			profile:       certProfile,
			subject:       csrSubject,
			extensions: func() []pkix.Extension {
				rawValues := []asn1.RawValue{}
				// nameTypeEmail = 1
				// nameTypeURI = 6
				nameTypeDNS := 2 //RFC 5280 > Section 4.2.1.6 https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
				nameTypeIP := 7

				ip := net.IP{192, 168, 10, 1}
				rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte("dev.lamassu.io")})
				rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip.To4()})
				val, _ := asn1.Marshal(rawValues)

				return []pkix.Extension{{
					Id:    asn1.ObjectIdentifier{2, 5, 29, 17}, // Subject Alternative Name OID
					Value: val,
				}}
			},
			keyType: models.KeyType(x509.ECDSA),
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: func(cert *x509.Certificate, tcSubject models.Subject, keyType models.KeyType, expirationTime time.Time, errCsr, errSign error) error {
				if err := checkOk(cert, tcSubject, keyType, expirationTime, errCsr, errSign); err != nil {
					return nil
				}

				if len(cert.IPAddresses) != 1 {
					return fmt.Errorf("expected 1 SAN IP address, got %d", len(cert.IPAddresses))
				}

				expectedIP := net.IP{192, 168, 10, 1}
				if !cert.IPAddresses[0].Equal(expectedIP) {
					return fmt.Errorf("IP address mismatch. Expected %s, got %s", cert.IPAddresses[0].String(), expectedIP.String())
				}

				if len(cert.DNSNames) != 1 {
					return fmt.Errorf("expected 1 SAN DNS name, got %d", len(cert.DNSNames))
				}

				if cert.DNSNames[0] != "dev.lamassu.io" {
					return fmt.Errorf("DNS name mismatch. Expected dev.lamassu.io, got %s", cert.DNSNames[0])
				}

				return nil
			},
		},
		{
			name:          "OK/KEY_USAGE",
			caCertificate: caCertificateEC,
			caSigner:      caSignerEC,
			profile: models.IssuanceProfile{
				Validity: models.Validity{
					Type: models.Time,
					Time: expirationTime,
				},
				SignAsCA:        false,
				KeyUsage:        models.X509KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageContentCommitment),
				HonorSubject:    true,
				HonorExtensions: true,
			},
			subject: csrSubject,
			keyType: models.KeyType(x509.ECDSA),
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			extensions: func() []pkix.Extension { return []pkix.Extension{} },
			check: func(cert *x509.Certificate, tcSubject models.Subject, keyType models.KeyType, expirationTime time.Time, errCsr, errSign error) error {
				if err := checkOk(cert, tcSubject, keyType, expirationTime, errCsr, errSign); err != nil {
					return nil
				}

				if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					return fmt.Errorf("missing key 'KeyUsageDigitalSignature' usage")
				}

				if cert.KeyUsage&x509.KeyUsageDataEncipherment == 0 {
					return fmt.Errorf("missing key 'KeyUsageDataEncipherment' usage")
				}

				if cert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
					return fmt.Errorf("missing key 'KeyUsageContentCommitment' usage")
				}

				if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
					return fmt.Errorf("unexpected key 'KeyUsageCRLSign' usage")
				}

				return nil
			},
		},
		{
			name:          "OK/EXT_KEY_USAGE",
			caCertificate: caCertificateEC,
			caSigner:      caSignerEC,
			profile: models.IssuanceProfile{
				Validity: models.Validity{
					Type: models.Time,
					Time: expirationTime,
				},
				SignAsCA: false,
				ExtendedKeyUsages: []models.X509ExtKeyUsage{
					models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
					models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth),
				},
				HonorSubject:    true,
				HonorExtensions: true,
			},
			subject: csrSubject,
			keyType: models.KeyType(x509.ECDSA),
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			extensions: func() []pkix.Extension { return []pkix.Extension{} },
			check: func(cert *x509.Certificate, tcSubject models.Subject, keyType models.KeyType, expirationTime time.Time, errCsr, errSign error) error {
				if err := checkOk(cert, tcSubject, keyType, expirationTime, errCsr, errSign); err != nil {
					return nil
				}

				expectedKeyUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
				for _, expectedKeyUsage := range expectedKeyUsages {
					if contains := slices.Contains(cert.ExtKeyUsage, expectedKeyUsage); !contains {
						return fmt.Errorf("missing key usage %d in signed cert", expectedKeyUsage)
					}
				}

				return nil
			},
		},
		{
			name:          "FAIL/NOT_EXISTENT_CA",
			caCertificate: caCertificateNotImported,
			profile:       certProfile,
			subject:       csrSubject,
			keyType:       models.KeyType(x509.ECDSA),
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkFail,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			csr, errCsr := chelpers.GenerateCertificateRequestWithExtensions(tc.subject, tc.extensions(), tc.key())
			cert, errSing := x509Engine.SignCertificateRequest(ctx, csr, tc.caCertificate, tc.caSigner, tc.profile)
			err := tc.check(cert, tc.subject, tc.keyType, expirationTime, errCsr, errSing)
			if err != nil {
				t.Errorf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestChameleonCertificateRequest(t *testing.T) {
	kmsSvc, x509Engine, err := setupX509TestSuite(t)
	if err != nil {
		t.Fatalf("setuf failed: %s", err)
	}

	ctx := context.Background()
	keyRSA, err := kmsSvc.CreateKey(ctx, services.CreateKeyInput{
		Algorithm: "RSA",
		Size: 2048,
		Name: "rootCA-RSA",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerRSA := beservice.NewKMSCryptoSigner(ctx, *keyRSA, kmsSvc)

	keyECDSA, err := kmsSvc.CreateKey(ctx, services.CreateKeyInput{
		Algorithm: "ECDSA",
		Size: 256,
		Name: "rootCA-ECDSA",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerECDSA := beservice.NewKMSCryptoSigner(ctx, *keyECDSA, kmsSvc)

	keyMLDSA, err := kmsSvc.CreateKey(ctx, services.CreateKeyInput{
		Algorithm: "ML-DSA",
		Size: 65,
		Name: "rootCA-MLDSA",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerMLDSA := beservice.NewKMSCryptoSigner(ctx, *keyMLDSA, kmsSvc)


	keyEd25519, err := kmsSvc.CreateKey(ctx, services.CreateKeyInput{
		Algorithm: "Ed25519",
		Size: 256,
		Name: "rootCA-MLDSA",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	caSignerEd25519 := beservice.NewKMSCryptoSigner(ctx, *keyEd25519, kmsSvc)

	// Create the Chameleon Root CAs

	caExpirationTime := time.Now().AddDate(2, 0, 0) // Set expiration time to 2 year from now
	expirationTime := time.Now().AddDate(1, 0, 0)   // Set expiration time to 1 year from now

	subject := models.Subject{
		CommonName: "Root CA",
	}

	validity := models.Validity{
		Type: models.Time,
		Time: caExpirationTime,
	}

	caCertificateRSAMLDSA, err := x509Engine.CreateChameleonRootCA(ctx, caSignerMLDSA, caSignerRSA, keyMLDSA.KeyID, keyRSA.KeyID, subject, validity)
	if err != nil {
		t.Fatalf("unexpected result in test case: %s", err)
	}

	caCertificateECMLDSA, err := x509Engine.CreateChameleonRootCA(ctx, caSignerMLDSA, caSignerECDSA, keyMLDSA.KeyID, keyRSA.KeyID, subject, validity)
	if err != nil {
		t.Fatalf("unexpected result in test case: %s", err)
	}

	caCertificateEd25519MLDSA, err := x509Engine.CreateChameleonRootCA(ctx, caSignerMLDSA, caSignerEd25519, keyMLDSA.KeyID, keyECDSA.KeyID, subject, validity)
	if err != nil {
		t.Fatalf("unexpected result in test case: %s", err)
	}

	caCertificateNotImported, notImportedDeltaKey, notImportedBaseKey, err := chelpers.GenerateSelfSignedChameleonCA(x509.MLDSA, x509.RSA, 365*24*time.Hour, "MyCA")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	csrSubject := models.Subject{
		CommonName:       "Subordinate CA",
		Organization:     "Lamassu IoT",
		OrganizationUnit: "CA",
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
	}

	checkOk := func(baseCert *x509.Certificate, tcSubject models.Subject, deltaKeyType, baseKeyType models.KeyType, expirationTime time.Time, errDeltaCsr, errBaseCsr, errSign error) error {
		if errDeltaCsr != nil {
			return fmt.Errorf("unexpected error in delta csr gen: %s", errDeltaCsr)
		}

		if errBaseCsr != nil {
			return fmt.Errorf("unexpected error in base csr gen: %s", errBaseCsr)
		}

		if errSign != nil {
			return fmt.Errorf("unexpected error in signature: %s", errSign)
		}

		// Reconstruct and check the delta certificate
		deltaCert, err := x509.ReconstructDeltaCertificate(baseCert)
		err = checkCertificate(deltaCert, tcSubject, deltaKeyType, expirationTime)
		if err != nil {
			return err
		}

		// Check the base certificate
		err = checkCertificate(baseCert, tcSubject, baseKeyType, expirationTime)
		if err != nil {
			return err
		}

		if baseCert.Subject.CommonName != tcSubject.CommonName {
			return fmt.Errorf("unexpected result, got: %s, want: %s", baseCert.Subject.CommonName, tcSubject.CommonName)
		}

		return nil
	}

	checkFail := func(baseCert *x509.Certificate, tcSubject models.Subject, deltaKeyType, baseKeyType models.KeyType, expirationTime time.Time, errDeltaCsr, errBaseCsr, errSign error) error {
		if errDeltaCsr != nil {
			return fmt.Errorf("unexpected error in delta csr gen: %s", errDeltaCsr)
		}

		if errBaseCsr != nil {
			return fmt.Errorf("unexpected error in base csr gen: %s", errBaseCsr)
		}

		if errSign != nil {
			return fmt.Errorf("unexpected error in signature: %s", errSign)
		}

		return nil
	}

	certProfile := models.IssuanceProfile{
		Validity: models.Validity{
			Type: models.Time,
			Time: expirationTime,
		},
		SignAsCA:     false,
		HonorSubject: true,
		KeyUsage:     models.X509KeyUsage(x509.KeyUsageKeyAgreement),
		ExtendedKeyUsages: []models.X509ExtKeyUsage{
			models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
		},
		HonorExtensions: true,
	}

	var testcases = []struct {
		name          string
		caCertificate *x509.Certificate
		deltaCaSigner crypto.Signer
		baseCaSigner  crypto.Signer
		profile       models.IssuanceProfile
		subject       models.Subject
		extensions    func() []pkix.Extension
		deltaKeyType  models.KeyType
		baseKeyType   models.KeyType
		deltaKey      func() any
		baseKey       func() any
		check         func(baseCert *x509.Certificate, tcSubject models.Subject, deltaKeyType, baseKeyType models.KeyType, expirationTime time.Time, errDeltaCsr, errBaseCsr, errSign error) error
	}{
		{
			name:          "OK/RSA-MLDSA_RSA-MLDSA",
			caCertificate: caCertificateRSAMLDSA,
			deltaCaSigner: caSignerMLDSA,
			baseCaSigner:  caSignerRSA,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			deltaKeyType:  models.KeyType(x509.MLDSA),
			deltaKey: func() any {
				key, _ := chelpers.GenerateMLDSAKey(65)
				return key
			},
			baseKeyType: models.KeyType(x509.RSA),
			baseKey: func() any {
				key, _ := chelpers.GenerateRSAKey(2048)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EC-MLDSA_EC-MLDSA",
			caCertificate: caCertificateECMLDSA,
			deltaCaSigner: caSignerMLDSA,
			baseCaSigner:  caSignerECDSA,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			deltaKeyType:  models.KeyType(x509.MLDSA),
			deltaKey: func() any {
				key, _ := chelpers.GenerateMLDSAKey(65)
				return key
			},
			baseKeyType: models.KeyType(x509.ECDSA),
			baseKey: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/Ed25519-MLDSA_Ed25519-MLDSA",
			caCertificate: caCertificateEd25519MLDSA,
			deltaCaSigner: caSignerMLDSA,
			baseCaSigner:  caSignerEd25519,
			profile:       certProfile,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			deltaKeyType:  models.KeyType(x509.MLDSA),
			deltaKey: func() any {
				key, _ := chelpers.GenerateMLDSAKey(65)
				return key
			},
			baseKeyType: models.KeyType(x509.Ed25519),
			baseKey: func() any {
				key, _ := chelpers.GenerateEd25519Key()
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EXT_SAN",
			caCertificate: caCertificateRSAMLDSA,
			deltaCaSigner: caSignerMLDSA,
			baseCaSigner:  caSignerRSA,
			profile:       certProfile,
			subject:       csrSubject,
			extensions: func() []pkix.Extension {
				rawValues := []asn1.RawValue{}
				// nameTypeEmail = 1
				// nameTypeURI = 6
				nameTypeDNS := 2 //RFC 5280 > Section 4.2.1.6 https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
				nameTypeIP := 7

				ip := net.IP{192, 168, 10, 1}
				rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte("dev.lamassu.io")})
				rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip.To4()})
				val, _ := asn1.Marshal(rawValues)

				return []pkix.Extension{{
					Id:    asn1.ObjectIdentifier{2, 5, 29, 17}, // Subject Alternative Name OID
					Value: val,
				}}
			},
			deltaKeyType: models.KeyType(x509.MLDSA),
			deltaKey: func() any {
				key, _ := chelpers.GenerateMLDSAKey(65)
				return key
			},
			baseKeyType: models.KeyType(x509.RSA),
			baseKey: func() any {
				key, _ := chelpers.GenerateRSAKey(2048)
				return key
			},
			check: func(baseCert *x509.Certificate, tcSubject models.Subject, deltaKeyType, baseKeyType models.KeyType, expirationTime time.Time, errDeltaCsr, errBaseCsr, errSign error) error {
				if err := checkOk(baseCert, tcSubject, deltaKeyType, baseKeyType, expirationTime, errDeltaCsr, errBaseCsr, errSign); err != nil {
					return nil
				}

				if len(baseCert.IPAddresses) != 1 {
					return fmt.Errorf("expected 1 SAN IP address, got %d", len(baseCert.IPAddresses))
				}

				expectedIP := net.IP{192, 168, 10, 1}
				if !baseCert.IPAddresses[0].Equal(expectedIP) {
					return fmt.Errorf("IP address mismatch. Expected %s, got %s", baseCert.IPAddresses[0].String(), expectedIP.String())
				}

				if len(baseCert.DNSNames) != 1 {
					return fmt.Errorf("expected 1 SAN DNS name, got %d", len(baseCert.DNSNames))
				}

				if baseCert.DNSNames[0] != "dev.lamassu.io" {
					return fmt.Errorf("DNS name mismatch. Expected dev.lamassu.io, got %s", baseCert.DNSNames[0])
				}

				return nil
			},
		},
		{
			name:          "OK/KEY_USAGE",
			caCertificate: caCertificateRSAMLDSA,
			deltaCaSigner: caSignerMLDSA,
			baseCaSigner:  caSignerRSA,
			profile: models.IssuanceProfile{
				Validity: models.Validity{
					Type: models.Time,
					Time: expirationTime,
				},
				SignAsCA:        false,
				KeyUsage:        models.X509KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageContentCommitment),
				HonorSubject:    true,
				HonorExtensions: true,
			},
			subject:      csrSubject,
			deltaKeyType: models.KeyType(x509.MLDSA),
			deltaKey: func() any {
				key, _ := chelpers.GenerateMLDSAKey(65)
				return key
			},
			baseKeyType: models.KeyType(x509.RSA),
			baseKey: func() any {
				key, _ := chelpers.GenerateRSAKey(2048)
				return key
			},
			extensions: func() []pkix.Extension { return []pkix.Extension{} },
			check: func(baseCert *x509.Certificate, tcSubject models.Subject, deltaKeyType, baseKeyType models.KeyType, expirationTime time.Time, errDeltaCsr, errBaseCsr, errSign error) error {
				err := checkOk(baseCert, tcSubject, deltaKeyType, baseKeyType, expirationTime, errDeltaCsr, errBaseCsr, errSign)
				if err != nil {
					return nil
				}

				if baseCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					return fmt.Errorf("missing key 'KeyUsageDigitalSignature' usage")
				}

				if baseCert.KeyUsage&x509.KeyUsageDataEncipherment == 0 {
					return fmt.Errorf("missing key 'KeyUsageDataEncipherment' usage")
				}

				if baseCert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
					return fmt.Errorf("missing key 'KeyUsageContentCommitment' usage")
				}

				if baseCert.KeyUsage&x509.KeyUsageCRLSign != 0 {
					return fmt.Errorf("unexpected key 'KeyUsageCRLSign' usage")
				}

				return nil
			},
		},
		{
			name:          "OK/EXT_KEY_USAGE",
			caCertificate: caCertificateRSAMLDSA,
			deltaCaSigner: caSignerMLDSA,
			baseCaSigner:  caSignerRSA,
			profile: models.IssuanceProfile{
				Validity: models.Validity{
					Type: models.Time,
					Time: expirationTime,
				},
				SignAsCA: false,
				ExtendedKeyUsages: []models.X509ExtKeyUsage{
					models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
					models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth),
				},
				HonorSubject:    true,
				HonorExtensions: true,
			},
			subject:      csrSubject,
			deltaKeyType: models.KeyType(x509.MLDSA),
			deltaKey: func() any {
				key, _ := chelpers.GenerateMLDSAKey(65)
				return key
			},
			baseKeyType: models.KeyType(x509.RSA),
			baseKey: func() any {
				key, _ := chelpers.GenerateRSAKey(2048)
				return key
			},
			extensions: func() []pkix.Extension { return []pkix.Extension{} },
			check: func(baseCert *x509.Certificate, tcSubject models.Subject, deltaKeyType, baseKeyType models.KeyType, expirationTime time.Time, errDeltaCsr, errBaseCsr, errSign error) error {
				if err := checkOk(baseCert, tcSubject, deltaKeyType, baseKeyType, expirationTime, errDeltaCsr, errBaseCsr, errSign); err != nil {
					return nil
				}

				// Check base certificate key usages
				expectedKeyUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
				for _, expectedKeyUsage := range expectedKeyUsages {
					if contains := slices.Contains(baseCert.ExtKeyUsage, expectedKeyUsage); !contains {
						return fmt.Errorf("missing key usage %d in signed cert", expectedKeyUsage)
					}
				}

				// Check delta certificate key usages
				deltaCert, err := x509.ReconstructDeltaCertificate(baseCert)
				if err != nil {
					return err
				}
				for _, expectedKeyUsage := range expectedKeyUsages {
					if contains := slices.Contains(deltaCert.ExtKeyUsage, expectedKeyUsage); !contains {
						return fmt.Errorf("missing key usage %d in signed cert", expectedKeyUsage)
					}
				}

				return nil
			},
		},
		{
			name:          "FAIL/NOT_EXISTENT_CA",
			caCertificate: caCertificateNotImported,
			deltaCaSigner: notImportedDeltaKey,
			baseCaSigner:  notImportedBaseKey,
			profile:       certProfile,
			subject:       csrSubject,
			deltaKeyType:  models.KeyType(x509.MLDSA),
			deltaKey: func() any {
				key, _ := chelpers.GenerateMLDSAKey(65)
				return key
			},
			baseKeyType: models.KeyType(x509.RSA),
			baseKey: func() any {
				key, _ := chelpers.GenerateRSAKey(2048)
				return key
			},
			extensions: func() []pkix.Extension { return []pkix.Extension{} },
			check:      checkFail,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			// Generate the CSR for both the traditional (base) and post-quantum (delta) certificates
			deltaCsr, errDeltaCsr := chelpers.GenerateCertificateRequestWithExtensions(tc.subject, tc.extensions(), tc.deltaKey())
			baseCsr, errBaseCsr := chelpers.GenerateCertificateRequestWithExtensions(tc.subject, tc.extensions(), tc.baseKey())
			cert, errSign := x509Engine.SignChameleonCertificateRequest(ctx, deltaCsr, baseCsr, tc.caCertificate, tc.deltaCaSigner, tc.baseCaSigner, tc.profile)
			err := tc.check(cert, tc.subject, tc.deltaKeyType, tc.baseKeyType, expirationTime, errDeltaCsr, errBaseCsr, errSign)
			if err != nil {
				t.Errorf("unexpected result in test case: %s", err)
			}
		})
	}
}
