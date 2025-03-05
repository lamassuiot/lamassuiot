package assemblers

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
)

func TestBaseCRL(t *testing.T) {
	serverTest, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not create VA test server")
	}

	var testcases = []struct {
		name        string
		before      func(services.CAService) ([]*models.Certificate, error)
		resultCheck func(certs []*models.Certificate, issuer *models.CACertificate, crl *x509.RevocationList, err error)
	}{
		{
			name: "OK/GetCRL-10-Certificates",
			before: func(caSDK services.CAService) ([]*models.Certificate, error) {
				crtsToIssue := 10
				crts := []*models.Certificate{}
				for i := 0; i < crtsToIssue; i++ {
					crt, err := generateCertificate(caSDK)
					if err != nil {
						return nil, err
					}

					crt, err = caSDK.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
						SerialNumber:     crt.SerialNumber,
						NewStatus:        models.StatusRevoked,
						RevocationReason: ocsp.Superseded,
					})
					if err != nil {
						return nil, err
					}

					crts = append(crts, crt)
				}

				// Sleep to ensure that the CRL is regenerated on revoke
				time.Sleep(5 * time.Second)
				return crts, nil
			},
			resultCheck: func(crts []*models.Certificate, issuer *models.CACertificate, crl *x509.RevocationList, err error) {
				if len(crl.RevokedCertificateEntries) != 10 {
					t.Fatalf("crl should have %d entries, got %d", len(crts), len(crl.RevokedCertificateEntries))
				}
			},
		},
		{
			name: "OK/CheckSignature",
			before: func(caSDK services.CAService) ([]*models.Certificate, error) {
				crtsToIssue := 10
				crts := []*models.Certificate{}
				for i := 0; i < crtsToIssue; i++ {
					crt, err := generateCertificate(caSDK)
					if err != nil {
						return nil, err
					}

					crt, err = caSDK.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
						SerialNumber:     crt.SerialNumber,
						NewStatus:        models.StatusRevoked,
						RevocationReason: ocsp.Superseded,
					})
					if err != nil {
						return nil, err
					}

					crts = append(crts, crt)
				}
				return crts, nil
			},
			resultCheck: func(crts []*models.Certificate, issuer *models.CACertificate, crl *x509.RevocationList, err error) {
				if err != nil {
					t.Fatalf("should've got CRL, but got error: %s", err)
				}

				if err = crl.CheckSignatureFrom((*x509.Certificate)(issuer.Certificate.Certificate)); err != nil {
					t.Fatalf("invalid CRL signature: %s", err)
				}
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			serverTest.BeforeEach()
			_, err := initCAForVA(serverTest)
			if err != nil {
				t.Fatalf("could not init CA for VA: %s", err)
			}
			issuerCA, err := serverTest.CA.Service.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
			if err != nil {
				t.Fatalf("could not get issuer CA: %s", err)
			}

			crts, err := tc.before(serverTest.CA.Service)
			if err != nil {
				t.Fatalf("could not run 'before' function:  %s", err)
			}

			time.Sleep(5 * time.Second) // Sleep to ensure that the CRL is generated (CRL is generated when the CA is created via event bus)

			crl, err := serverTest.VA.HttpVASDK.GetCRL(context.Background(), services.GetCRLResponseInput{
				CASubjectKeyID: issuerCA.Certificate.AuthorityKeyID,
				Issuer:         (*x509.Certificate)(issuerCA.Certificate.Certificate),
				VerifyResponse: true,
			})
			if err != nil {
				t.Fatalf("could not get CRL: %s", err)
			}

			tc.resultCheck(crts, issuerCA, crl, err)
		})
	}
}

func TestCRLCertificateRevocation(t *testing.T) {
	serverTest, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not create VA test server")
	}

	caSDK := serverTest.CA.HttpCASDK

	serverTest.BeforeEach()
	ca, err := initCAForVA(serverTest)
	if err != nil {
		t.Fatalf("could not init CA for VA: %s", err)
	}

	crtsToIssue := 10
	issuedCertsSNs := []string{}
	var oneCrt *models.Certificate
	for i := 0; i < crtsToIssue; i++ {
		crt, err := generateCertificate(caSDK)
		oneCrt = crt
		if err != nil {
			t.Fatalf("could not generate certificate: %s", err)
		}

		issuedCertsSNs = append(issuedCertsSNs, crt.SerialNumber)
	}

	time.Sleep(3 * time.Second) // Sleep to ensure that the CRL is generated (CRL is generated when the CA is created via event bus)

	// By Default, a VARole is created for the CA automatically setting the CRL to be regenerated on revoke
	// First get v1 CRL and check that it has 0 entries
	crl, err := serverTest.VA.HttpVASDK.GetCRL(context.Background(), services.GetCRLResponseInput{
		CASubjectKeyID: oneCrt.AuthorityKeyID,
		Issuer:         (*x509.Certificate)(ca.Certificate.Certificate),
		VerifyResponse: true,
	})
	if err != nil {
		t.Fatalf("could not get CRL: %s", err)
	}

	assert.Equal(t, 0, len(crl.RevokedCertificateEntries), "CRL should have 0 entries")
	assert.Equal(t, big.NewInt(1), crl.Number, "CRL should have version 1")

	// Revoke a certificate
	rndSN := issuedCertsSNs[rand.Intn(len(issuedCertsSNs))]
	_, err = caSDK.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
		SerialNumber:     rndSN,
		NewStatus:        models.StatusRevoked,
		RevocationReason: ocsp.CessationOfOperation,
	})

	assert.NoError(t, err, "could not revoke certificate: %s", err)

	// Sleep to ensure that the CRL is regenerated. Since the CRL is generated on revoke via event bus, it may take some time.
	time.Sleep(5 * time.Second)

	// Get v2 CRL and check that it has 1 entry
	crl, err = serverTest.VA.HttpVASDK.GetCRL(context.Background(), services.GetCRLResponseInput{
		CASubjectKeyID: oneCrt.AuthorityKeyID,
		Issuer:         (*x509.Certificate)(ca.Certificate.Certificate),
		VerifyResponse: true,
	})
	if err != nil {
		t.Fatalf("could not get CRL: %s", err)
	}

	assert.Equal(t, 1, len(crl.RevokedCertificateEntries), "CRL should have 1 entry")
	assert.Equal(t, big.NewInt(2), crl.Number, "CRL should have version 2")
}

func TestPostOCSP(t *testing.T) {
	t.Parallel()

	serverTest, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not create VA test server")
	}

	serverTest.BeforeEach()
	_, err = initCAForVA(serverTest)
	if err != nil {
		t.Fatalf("could not init CA for VA: %s", err)
	}

	var testcases = []struct {
		name        string
		before      func(services.CAService, *models.Certificate) error
		resultCheck func(*models.Certificate, *models.CACertificate, *ocsp.Response, error) error
	}{
		{
			name:   "OK/Valid-OCSP-Signature",
			before: func(caSDK services.CAService, crt *models.Certificate) error { return nil },
			resultCheck: func(crt *models.Certificate, issuer *models.CACertificate, response *ocsp.Response, err error) error {
				if err != nil {
					return fmt.Errorf("should've got OCSP Response, but got error: %s", err)
				}

				if helpers.SerialNumberToString(response.SerialNumber) != crt.SerialNumber {
					return fmt.Errorf("ocsp response has different serial number than the certificate. Got %s, should've got %s", helpers.SerialNumberToString(response.SerialNumber), crt.SerialNumber)
				}

				if err = response.CheckSignatureFrom((*x509.Certificate)(issuer.Certificate.Certificate)); err != nil {
					return fmt.Errorf("invalid signature in OCSP Response: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/Active-Certificates",
			before: func(caSDK services.CAService, crt *models.Certificate) error { return nil },
			resultCheck: func(crt *models.Certificate, issuer *models.CACertificate, response *ocsp.Response, err error) error {
				if err != nil {
					return fmt.Errorf("should've got OCSP Response, but got error: %s", err)
				}

				if response.Status != ocsp.Good {
					return fmt.Errorf("should've been in Good status, got status: %d", response.Status)
				}

				return nil
			},
		},
		{
			name: "OK/Revoked-Certificate",
			before: func(caSDK services.CAService, crt *models.Certificate) error {
				_, err := caSDK.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
					SerialNumber:     crt.SerialNumber,
					NewStatus:        models.StatusRevoked,
					RevocationReason: ocsp.Unspecified,
				})
				return err
			},
			resultCheck: func(crt *models.Certificate, issuer *models.CACertificate, response *ocsp.Response, err error) error {
				if err != nil {
					return fmt.Errorf("should've got OCSP Response, but got error: %s", err)
				}

				if response.Status != ocsp.Revoked {
					return fmt.Errorf("should've been in Revoke status, got status: %d", response.Status)
				}

				if response.RevocationReason != ocsp.Unspecified {
					return fmt.Errorf("should've got Unspecified revocation reason, got status: %d", response.RevocationReason)
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			crt, err := generateCertificate(serverTest.CA.Service)
			if err != nil {
				t.Fatalf("failed generating crt in test case: %s", err)
			}

			issuerCA, err := serverTest.CA.Service.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
			if err != nil {
				t.Fatalf("could not get issuer CA: %s", err)
			}

			err = tc.before(serverTest.CA.Service, crt)
			if err != nil {
				t.Fatalf("could not run before OCSP Request-Response: %s", err)
			}

			response, err := serverTest.VA.HttpVASDK.GetOCSPResponsePost(context.Background(), services.GetOCSPResponseInput{
				Certificate:    (*x509.Certificate)(crt.Certificate),
				Issuer:         (*x509.Certificate)(issuerCA.Certificate.Certificate),
				VerifyResponse: true,
			})
			err = tc.resultCheck(crt, issuerCA, response, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}
func TestGetOCSP(t *testing.T) {
	t.Skip("Skipping test for now")
	serverTest, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not create VA test server")
	}
	serverTest.BeforeEach()
	_, err = initCAForVA(serverTest)
	if err != nil {
		t.Fatalf("could not init CA for VA: %s", err)
	}

	issuerCA, err := serverTest.CA.Service.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
	if err != nil {
		t.Fatalf("could not get issuer CA: %s", err)
	}

	crt, err := generateCertificate(serverTest.CA.Service)
	if err != nil {
		t.Fatalf("failed generating crt in test case: %s", err)
	}

	response, err := serverTest.VA.HttpVASDK.GetOCSPResponseGet(context.Background(), services.GetOCSPResponseInput{
		Certificate:    (*x509.Certificate)(crt.Certificate),
		Issuer:         (*x509.Certificate)(issuerCA.Certificate.Certificate),
		VerifyResponse: true,
	})
	if err != nil {
		t.Fatalf("failed getting OCSP response: %s", err)
	}

	if response.Status != ocsp.Good {
		t.Errorf("should've been in Good status, got status: %d", response.Status)
	}
}

func TestCheckOCSPRevocationCodes(t *testing.T) {
	var testcases = map[int]string{
		ocsp.Unspecified:          "Unspecified",
		ocsp.KeyCompromise:        "KeyCompromise",
		ocsp.CACompromise:         "CACompromise",
		ocsp.AffiliationChanged:   "AffiliationChanged",
		ocsp.Superseded:           "Superseded",
		ocsp.CessationOfOperation: "CessationOfOperation",
		ocsp.CertificateHold:      "CertificateHold",
		ocsp.RemoveFromCRL:        "RemoveFromCRL",
		ocsp.PrivilegeWithdrawn:   "PrivilegeWithdrawn",
		ocsp.AACompromise:         "AACompromise",
	}

	serverTest, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not create VA test server")
	}
	serverTest.BeforeEach()
	_, err = initCAForVA(serverTest)
	if err != nil {
		t.Fatalf("could not init CA for VA: %s", err)
	}

	issuerCA, err := serverTest.CA.Service.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
	if err != nil {
		t.Fatalf("could not get issuer CA: %s", err)
	}

	for reason, reasonName := range testcases {
		t.Run(fmt.Sprintf("Revocation-%s", reasonName), func(t *testing.T) {
			crt, err := generateCertificate(serverTest.CA.Service)
			if err != nil {
				t.Fatalf("failed generating crt in test case: %s", err)
			}

			_, err = serverTest.CA.Service.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
				SerialNumber:     crt.SerialNumber,
				NewStatus:        models.StatusRevoked,
				RevocationReason: models.RevocationReason(reason),
			})
			if err != nil {
				t.Fatalf("failed revoking certificate: %s", err)
			}

			response, err := serverTest.VA.HttpVASDK.GetOCSPResponsePost(context.Background(), services.GetOCSPResponseInput{
				Certificate:    (*x509.Certificate)(crt.Certificate),
				Issuer:         (*x509.Certificate)(issuerCA.Certificate.Certificate),
				VerifyResponse: true,
			})
			if err != nil {
				t.Fatalf("failed getting OCSP response: %s", err)
			}

			if response.Status != ocsp.Revoked {
				t.Errorf("should've been in Revoke status, got status: %d", response.Status)
			}

			if response.RevocationReason != reason {
				t.Fatalf("should've got %s revocation reason, got status: %d", reasonName, response.RevocationReason)
			}
		})
	}
}

func generateCertificate(caSDK services.CAService) (*models.Certificate, error) {
	key, err := chelpers.GenerateRSAKey(2048)
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %s", err)
	}

	csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "my-cert"}, key)
	if err != nil {
		return nil, fmt.Errorf("could not generate csr: %s", err)
	}

	ca, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
	if err != nil {
		return nil, fmt.Errorf("could not get CA: %s", err)
	}

	crt, err := caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
		CAID:        DefaultCAID,
		CertRequest: (*models.X509CertificateRequest)(csr),
		IssuanceProfile: models.IssuanceProfile{
			Validity:        ca.Validity,
			SignAsCA:        false,
			HonorSubject:    true,
			HonorExtensions: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("could not sign csr: %s", err)
	}

	return crt, nil
}

func StartVAServiceTestServer(t *testing.T) (*TestServer, error) {
	testServer, err := TestServiceBuilder{}.WithDatabase("ca", "va").WithService(CA, VA).WithMonitor().WithEventBus().Build(t)
	if err != nil {
		return nil, fmt.Errorf("could not create Device Manager test server: %s", err)
	}
	return testServer, nil
}

func initCAForVA(testServer *TestServer) (*models.CACertificate, error) {
	//Init CA Server with 1 CA
	caDUr := models.TimeDuration(time.Hour * 24)
	issuanceDur := models.TimeDuration(time.Hour * 12)
	ca, err := testServer.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
		ID:                 DefaultCAID,
		KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:            models.Subject{CommonName: "TestCA"},
		CAExpiration:       models.Validity{Type: models.Duration, Duration: caDUr},
		IssuanceExpiration: models.Validity{Type: models.Duration, Duration: issuanceDur},
	})
	if err != nil {
		return nil, err
	}
	return ca, nil
}

//Hacer la función de test de getCRL
