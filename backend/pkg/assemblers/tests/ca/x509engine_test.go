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
