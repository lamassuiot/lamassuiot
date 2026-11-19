package va

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
)

// DefaultCAID is the ID of the CA that initCAForVA creates. Every call creates a CA with a new ID: the VA works with
// events delivered asynchronously and routes them by CA ID, so a late event of a previous test must not find the CA of
// the next one.
var DefaultCAID string

func TestBaseCRL(t *testing.T) {
	vaTestServer, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not start VA service test server: %s", err)
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
				for range crtsToIssue {
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
				for range crtsToIssue {
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

		t.Run(tc.name, func(t *testing.T) {
			err := serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("could not run BeforeEach: %s", err)
			}
			_, err = initCAForVA(vaTestServer.HttpCASDK)
			if err != nil {
				t.Fatalf("could not init CA for VA: %s", err)
			}
			issuerCA, err := vaTestServer.HttpCASDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
			if err != nil {
				t.Fatalf("could not get issuer CA: %s", err)
			}

			crts, err := tc.before(vaTestServer.HttpCASDK)
			if err != nil {
				t.Fatalf("could not run 'before' function:  %s", err)
			}

			var crl *x509.RevocationList
			err = tests.SleepRetry(5, 5*time.Second, func() error {
				crl, err = vaTestServer.HttpVASDK.GetCRL(context.Background(), services.GetCRLResponseInput{
					ID:             issuerCA.ID,
					Issuer:         (*x509.Certificate)(issuerCA.Certificate.Certificate),
					VerifyResponse: true,
				})

				return err
			})
			if err != nil {
				t.Fatalf("could not get CRL: %s", err)
			}

			tc.resultCheck(crts, issuerCA, crl, err)
		})
	}
}

func TestCRLCertificateRevocation(t *testing.T) {
	vaTestServer, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not start VA service test server: %s", err)
	}
	ca, err := initCAForVA(vaTestServer.HttpCASDK)
	if err != nil {
		t.Fatalf("could not init CA for VA: %s", err)
	}

	crtsToIssue := 10
	issuedCertsSNs := []string{}
	var oneCrt *models.Certificate
	for range crtsToIssue {
		crt, err := generateCertificate(vaTestServer.HttpCASDK)
		oneCrt = crt
		if err != nil {
			t.Fatalf("could not generate certificate: %s", err)
		}

		issuedCertsSNs = append(issuedCertsSNs, crt.SerialNumber)
	}

	var crl *x509.RevocationList
	// Sleep to ensure that the CRL is generated (CRL is generated when the CA is created via event bus)
	err = tests.SleepRetry(5, 3*time.Second, func() error {
		// By Default, CRL settings are created for the CA automatically setting the CRL to be regenerated on revoke
		// First get v1 CRL and check that it has 0 entries
		crl, err = vaTestServer.HttpVASDK.GetCRL(context.Background(), services.GetCRLResponseInput{
			ID:             oneCrt.IssuerCAMetadata.ID,
			Issuer:         (*x509.Certificate)(ca.Certificate.Certificate),
			VerifyResponse: true,
		})

		if err != nil {
			return err
		}

		if len(crl.RevokedCertificateEntries) != 0 {
			return fmt.Errorf("CRL should have 0 entry, got %d", len(crl.RevokedCertificateEntries))
		}

		if big.NewInt(1).Cmp(crl.Number) != 0 {
			return fmt.Errorf("CRL should have version 1, got %d", crl.Number)
		}

		return nil
	})

	if err != nil {
		t.Fatalf("could not get CRL: %s", err)
	}

	assert.Equal(t, 0, len(crl.RevokedCertificateEntries), "CRL should have 0 entries")
	assert.Equal(t, big.NewInt(1), crl.Number, "CRL should have version 1")

	// Revoke a certificate
	rndSN := issuedCertsSNs[rand.Intn(len(issuedCertsSNs))]
	_, err = vaTestServer.HttpCASDK.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
		SerialNumber:     rndSN,
		NewStatus:        models.StatusRevoked,
		RevocationReason: ocsp.CessationOfOperation,
	})

	assert.NoError(t, err, "could not revoke certificate: %s", err)

	// Sleep to ensure that the CRL is regenerated. Since the CRL is generated on revoke via event bus, it may take some time.
	err = tests.SleepRetry(5, 3*time.Second, func() error {
		// Get v2 CRL and check that it has 1 entry
		crl, err = vaTestServer.HttpVASDK.GetCRL(context.Background(), services.GetCRLResponseInput{
			ID:             oneCrt.IssuerCAMetadata.ID,
			Issuer:         (*x509.Certificate)(ca.Certificate.Certificate),
			VerifyResponse: true,
		})

		if err != nil {
			return err
		}

		if len(crl.RevokedCertificateEntries) != 1 {
			return fmt.Errorf("CRL should have 1 entry, got %d", len(crl.RevokedCertificateEntries))
		}

		if big.NewInt(2).Cmp(crl.Number) != 0 {
			return fmt.Errorf("CRL should have version 2, got %d", crl.Number)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("could not get CRL: %s", err)
	}
	assert.Equal(t, 1, len(crl.RevokedCertificateEntries), "CRL should have 1 entry")
	assert.Equal(t, big.NewInt(2), crl.Number, "CRL should have version 2")
}

func TestPostOCSP(t *testing.T) {
	vaTestServer, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not start VA service test server: %s", err)
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

				if helpers.SerialNumberToHexString(response.SerialNumber) != crt.SerialNumber {
					return fmt.Errorf("ocsp response has different serial number than the certificate. Got %s, should've got %s", helpers.SerialNumberToHexString(response.SerialNumber), crt.SerialNumber)
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

		t.Run(tc.name, func(t *testing.T) {
			err := serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("could not run BeforeEach: %s", err)
			}
			_, err = initCAForVA(vaTestServer.HttpCASDK)
			if err != nil {
				t.Fatalf("could not init CA for VA: %s", err)
			}
			crt, err := generateCertificate(vaTestServer.HttpCASDK)
			if err != nil {
				t.Fatalf("failed generating crt in test case: %s", err)
			}

			issuerCA, err := vaTestServer.HttpCASDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
			if err != nil {
				t.Fatalf("could not get issuer CA: %s", err)
			}

			err = tc.before(vaTestServer.HttpCASDK, crt)
			if err != nil {
				t.Fatalf("could not run before OCSP Request-Response: %s", err)
			}

			response, err := vaTestServer.HttpVASDK.GetOCSPResponsePost(context.Background(), services.GetOCSPResponseInput{
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
	vaServerTest, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not start VA service test server: %s", err)
	}
	_, err = initCAForVA(vaServerTest.HttpCASDK)
	if err != nil {
		t.Fatalf("could not init CA for VA: %s", err)
	}

	issuerCA, err := vaServerTest.HttpCASDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
	if err != nil {
		t.Fatalf("could not get issuer CA: %s", err)
	}

	crt, err := generateCertificate(vaServerTest.HttpCASDK)
	if err != nil {
		t.Fatalf("failed generating crt in test case: %s", err)
	}

	response, err := vaServerTest.HttpVASDK.GetOCSPResponseGet(context.Background(), services.GetOCSPResponseInput{
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

	vaServerTest, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not start VA service test server: %s", err)
	}

	for reason, reasonName := range testcases {
		t.Run(fmt.Sprintf("Revocation-%s", reasonName), func(t *testing.T) {
			err := serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("could not run BeforeEach: %s", err)
			}
			_, err = initCAForVA(vaServerTest.HttpCASDK)
			if err != nil {
				t.Fatalf("could not init CA for VA: %s", err)
			}
			issuerCA, err := vaServerTest.HttpCASDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
			if err != nil {
				t.Fatalf("could not get issuer CA: %s", err)
			}
			crt, err := generateCertificate(vaServerTest.HttpCASDK)
			if err != nil {
				t.Fatalf("failed generating crt in test case: %s", err)
			}

			_, err = vaServerTest.HttpCASDK.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
				SerialNumber:     crt.SerialNumber,
				NewStatus:        models.StatusRevoked,
				RevocationReason: models.RevocationReason(reason),
			})
			if err != nil {
				t.Fatalf("failed revoking certificate: %s", err)
			}

			response, err := vaServerTest.HttpVASDK.GetOCSPResponsePost(context.Background(), services.GetOCSPResponseInput{
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

func TestCRLSettings(t *testing.T) {
	vaServerTest, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not start VA service test server: %s", err)
	}
	ca, err := initCAForVA(vaServerTest.HttpCASDK)
	if err != nil {
		t.Fatalf("could not init CA for VA: %s", err)
	}

	var role *models.CRLSettings
	err = tests.SleepRetry(5, 3*time.Second, func() error {
		role, err = vaServerTest.CRLService.GetCRLSettings(context.Background(), services.GetCRLSettingsInput{
			CAID: ca.ID,
		})

		return err
	})
	if err != nil {
		t.Fatalf("could not get role: %s", err)
	}

	if role.CAID != ca.ID {
		t.Fatalf("settings CAID should be %s, got %s", ca.ID, role.CAID)
	}

	if role.Options.RegenerateOnRevoke != true {
		t.Fatalf("role CRLOptions.RegenerateOnRevoke should be true, got %t", role.Options.RegenerateOnRevoke)
	}

	if role.Options.SignerSerialNumber != ca.Certificate.SerialNumber {
		t.Fatalf("role CRLOptions.SignerCertificateSerialNumber should be %s, got %s", ca.Certificate.SerialNumber, role.Options.SignerSerialNumber)
	}

	//Now Update the role

	role.Options.RegenerateOnRevoke = false
	role.Options.SignerSerialNumber = ca.Certificate.SerialNumber
	role.Options.Validity = models.TimeDuration(time.Hour * 2)

	role, err = serverTest.VA.CRLService.UpdateCRLSettings(context.Background(), services.UpdateCRLSettingsInput{
		CAID:    ca.ID,
		Options: role.Options,
	})

	if err != nil {
		t.Fatalf("could not update role: %s", err)
	}

	role, err = serverTest.VA.CRLService.GetCRLSettings(context.Background(), services.GetCRLSettingsInput{
		CAID: ca.ID,
	})

	if err != nil {
		t.Fatalf("could not get role: %s", err)
	}

	if role.Options.RegenerateOnRevoke != false {
		t.Fatalf("role CRLOptions.RegenerateOnRevoke should be false, got %t", role.Options.RegenerateOnRevoke)
	}

	if role.Options.SignerSerialNumber != ca.Certificate.SerialNumber {
		t.Fatalf("role CRLOptions.SignerCertificateSerialNumber should be %s, got %s", ca.Certificate.SerialNumber, role.Options.SignerSerialNumber)
	}

	//Now get all roles
	ctr := 0
	tests.SleepRetry(10, 3*time.Second, func() error {
		ctr = 0
		_, err = serverTest.VA.CRLService.GetCRLSettingsList(context.Background(), services.GetCRLSettingsListInput{
			ExhaustiveRun:   true,
			QueryParameters: &resources.QueryParameters{},
			ApplyFunc: func(role models.CRLSettings) {
				ctr++
			},
		})
		if err != nil {
			return err
		}

		if ctr != 1 {
			return fmt.Errorf("should've got 1 roles, got %d", ctr)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("could not get roles: %s", err)
	}

	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 12)},
		},
	})
	if err != nil {
		t.Fatalf("could not create issuance profile: %s", err)
	}

	//Create New CA and check if the role is created automatically
	ca, err = serverTest.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "TestCA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24)},
		ProfileID:    profile.ID,
	})
	if err != nil {
		t.Fatalf("could not create new CA: %s", err)
	}

	err = tests.SleepRetry(10, 3*time.Second, func() error {
		role, err = serverTest.VA.CRLService.GetCRLSettings(context.Background(), services.GetCRLSettingsInput{
			CAID: ca.ID,
		})

		return err
	})
	if err != nil {
		t.Fatalf("could not get role: %s", err)
	}

	if role.CAID != ca.ID {
		t.Fatalf("settings CAID should be %s, got %s", ca.ID, role.CAID)
	}

	tests.SleepRetry(10, 3*time.Second, func() error {
		ctr = 0
		_, err = serverTest.VA.CRLService.GetCRLSettingsList(context.Background(), services.GetCRLSettingsListInput{
			ExhaustiveRun:   true,
			QueryParameters: &resources.QueryParameters{},
			ApplyFunc: func(role models.CRLSettings) {
				ctr++
			},
		})
		if err != nil {
			return err
		}

		if ctr != 2 {
			return fmt.Errorf("should've got 2 roles, got %d", ctr)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("could not get roles: %s", err)
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
		CAID:              DefaultCAID,
		CertRequest:       (*models.X509CertificateRequest)(csr),
		IssuanceProfileID: ca.ProfileID,
	})
	if err != nil {
		return nil, fmt.Errorf("could not sign csr: %s", err)
	}

	return crt, nil
}

func initCAForVA(caSvc services.CAService) (*models.CACertificate, error) {
	//Init CA Server with 1 CA
	caDUr := models.TimeDuration(time.Hour * 24)
	issuanceDur := models.TimeDuration(time.Hour * 12)

	profile, err := caSvc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
		},
	})
	if err != nil {
		return nil, err
	}

	ca, err := caSvc.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "TestCA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
		ProfileID:    profile.ID,
	})
	if err != nil {
		return nil, err
	}

	DefaultCAID = ca.ID
	return ca, nil
}

func TestCRLCertificateReactivationFromHold(t *testing.T) {
	vaServerTest, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not start VA service test server: %s", err)
	}
	if err := vaServerTest.BeforeEach(); err != nil {
		t.Fatalf("could not run BeforeEach: %s", err)
	}
	ca, err := initCAForVA(vaServerTest.HttpCASDK)
	if err != nil {
		t.Fatalf("could not initialize CA: %s", err)
	}

	// Issue a test certificate
	oneCrt, err := generateCertificate(vaServerTest.HttpCASDK)
	if err != nil {
		t.Fatalf("could not generate certificate: %s", err)
	}

	// Sleep to ensure that the CRL is generated (CRL is generated when the CA is created via event bus)
	var crl *x509.RevocationList
	err = tests.SleepRetry(5, 3*time.Second, func() error {
		// First get v1 CRL and check that it has 0 entries
		crl, err = vaServerTest.HttpVASDK.GetCRL(context.Background(), services.GetCRLResponseInput{
			ID:             oneCrt.IssuerCAMetadata.ID,
			Issuer:         (*x509.Certificate)(ca.Certificate.Certificate),
			VerifyResponse: true,
		})

		if err != nil {
			return err
		}

		if len(crl.RevokedCertificateEntries) != 0 {
			return fmt.Errorf("CRL should have 0 entry, got %d", len(crl.RevokedCertificateEntries))
		}

		if big.NewInt(1).Cmp(crl.Number) != 0 {
			return fmt.Errorf("CRL should have version 1, got %d", crl.Number)
		}

		return nil
	})

	if err != nil {
		t.Fatalf("could not get initial CRL: %s", err)
	}

	assert.Equal(t, 0, len(crl.RevokedCertificateEntries), "CRL should have 0 entries initially")
	assert.Equal(t, big.NewInt(1), crl.Number, "CRL should have version 1 initially")

	// Revoke the certificate with CertificateHold reason
	_, err = vaServerTest.HttpCASDK.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
		SerialNumber:     oneCrt.SerialNumber,
		NewStatus:        models.StatusRevoked,
		RevocationReason: ocsp.CertificateHold,
	})

	assert.NoError(t, err, "could not revoke certificate with CertificateHold: %s", err)

	// Sleep to ensure that the CRL is regenerated after revocation
	err = tests.SleepRetry(5, 3*time.Second, func() error {
		// Get v2 CRL and check that it has 1 entry
		crl, err = vaServerTest.HttpVASDK.GetCRL(context.Background(), services.GetCRLResponseInput{
			ID:             oneCrt.IssuerCAMetadata.ID,
			Issuer:         (*x509.Certificate)(ca.Certificate.Certificate),
			VerifyResponse: true,
		})

		if err != nil {
			return err
		}

		if len(crl.RevokedCertificateEntries) != 1 {
			return fmt.Errorf("CRL should have 1 entry after revocation, got %d", len(crl.RevokedCertificateEntries))
		}

		if big.NewInt(2).Cmp(crl.Number) != 0 {
			return fmt.Errorf("CRL should have version 2 after revocation, got %d", crl.Number)
		}

		// Verify the revoked certificate is in the CRL with correct reason
		revokedEntry := crl.RevokedCertificateEntries[0]
		if revokedEntry.SerialNumber.Cmp(oneCrt.Certificate.SerialNumber) != 0 {
			return fmt.Errorf("revoked certificate serial number mismatch")
		}

		if revokedEntry.ReasonCode != int(ocsp.CertificateHold) {
			return fmt.Errorf("expected revocation reason CertificateHold (%d), got %d", int(ocsp.CertificateHold), revokedEntry.ReasonCode)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("could not get CRL after revocation: %s", err)
	}

	assert.Equal(t, 1, len(crl.RevokedCertificateEntries), "CRL should have 1 entry after revocation")
	assert.Equal(t, big.NewInt(2), crl.Number, "CRL should have version 2 after revocation")

	// Now reactivate the certificate (remove from CertificateHold)
	_, err = vaServerTest.HttpCASDK.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
		SerialNumber: oneCrt.SerialNumber,
		NewStatus:    models.StatusActive,
		// No revocation reason needed when reactivating
	})

	assert.NoError(t, err, "could not reactivate certificate from CertificateHold: %s", err)

	// Sleep to ensure that the CRL is regenerated after reactivation
	err = tests.SleepRetry(5, 3*time.Second, func() error {
		// Get v3 CRL and check that it has 0 entries (certificate should be removed)
		crl, err = vaServerTest.HttpVASDK.GetCRL(context.Background(), services.GetCRLResponseInput{
			ID:             oneCrt.IssuerCAMetadata.ID,
			Issuer:         (*x509.Certificate)(ca.Certificate.Certificate),
			VerifyResponse: true,
		})

		if err != nil {
			return err
		}

		if len(crl.RevokedCertificateEntries) != 0 {
			return fmt.Errorf("CRL should have 0 entries after reactivation, got %d", len(crl.RevokedCertificateEntries))
		}

		if big.NewInt(3).Cmp(crl.Number) != 0 {
			return fmt.Errorf("CRL should have version 3 after reactivation, got %d", crl.Number)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("could not get CRL after reactivation: %s", err)
	}

	assert.Equal(t, 0, len(crl.RevokedCertificateEntries), "CRL should have 0 entries after reactivation - certificate should be removed from CRL")
	assert.Equal(t, big.NewInt(3), crl.Number, "CRL should have version 3 after reactivation")
}

//Hacer la función de test de getCRL
