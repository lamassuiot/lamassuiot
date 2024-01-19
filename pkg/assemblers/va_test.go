package assemblers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"golang.org/x/crypto/ocsp"
)

func TestCRL(t *testing.T) {
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
				return crts, nil
			},
			resultCheck: func(crts []*models.Certificate, issuer *models.CACertificate, crl *x509.RevocationList, err error) {
				if len(crl.RevokedCertificateEntries) != len(crts) {
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
			vaTest, err := BuildVATestServer(t)
			if err != nil {
				t.Fatalf("could not create VA test server")
			}

			issuerCA, err := vaTest.CaSDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
			if err != nil {
				t.Fatalf("could not get issuer CA: %s", err)
			}

			crts, err := tc.before(vaTest.CaSDK)
			if err != nil {
				t.Fatalf("could not run 'before' function:  %s", err)
			}

			httpRequest, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/crl/%s", vaTest.HttpServerURL, DefaultCAID), nil)
			if err != nil {
				t.Fatalf("could not generate HTTP CRL request: %s", err)
			}

			httpClient := &http.Client{}
			httpResponse, err := httpClient.Do(httpRequest)
			if err != nil {
				t.Fatalf("could not DO CRL request: %s", err)
			}

			defer httpResponse.Body.Close()
			output, err := io.ReadAll(httpResponse.Body)
			if err != nil {
				t.Fatalf("could not read response body: %s", err)
			}

			crl, err := x509.ParseRevocationList(output)
			tc.resultCheck(crts, issuerCA, crl, err)
		})
	}
}

func TestPostOCSP(t *testing.T) {
	t.Parallel()

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
			vaTest, err := BuildVATestServer(t)
			if err != nil {
				t.Fatalf("could not create VA test server")
			}

			crt, err := generateCertificate(vaTest.CaSDK)
			if err != nil {
				t.Fatalf("failed generating crt in test case: %s", err)
			}

			issuerCA, err := vaTest.CaSDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
			if err != nil {
				t.Fatalf("could not get issuer CA: %s", err)
			}

			err = tc.before(vaTest.CaSDK, crt)
			if err != nil {
				t.Fatalf("could not run before OCSP Request-Response: %s", err)
			}

			response, err := getOCSPResponsePost(vaTest.HttpServerURL, crt, issuerCA)

			err = tc.resultCheck(crt, issuerCA, response, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}
func TestGetOCSP(t *testing.T) {
	t.Skip("Skip until we have a reliable way to test this")
	vaTest, err := BuildVATestServer(t)
	if err != nil {
		t.Fatalf("could not create VA test server")
	}

	issuerCA, err := vaTest.CaSDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
	if err != nil {
		t.Fatalf("could not get issuer CA: %s", err)
	}

	crt, err := generateCertificate(vaTest.CaSDK)
	if err != nil {
		t.Fatalf("failed generating crt in test case: %s", err)
	}

	response, err := getOCSPResponseGet(vaTest.HttpServerURL, crt, issuerCA)
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

	vaTest, err := BuildVATestServer(t)
	if err != nil {
		t.Fatalf("could not create VA test server")
	}

	issuerCA, err := vaTest.CaSDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
	if err != nil {
		t.Fatalf("could not get issuer CA: %s", err)
	}

	for reason, reasonName := range testcases {
		t.Run(fmt.Sprintf("Revocation-%s", reasonName), func(t *testing.T) {
			crt, err := generateCertificate(vaTest.CaSDK)
			if err != nil {
				t.Fatalf("failed generating crt in test case: %s", err)
			}

			_, err = vaTest.CaSDK.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
				SerialNumber:     crt.SerialNumber,
				NewStatus:        models.StatusRevoked,
				RevocationReason: models.RevocationReason(reason),
			})
			if err != nil {
				t.Fatalf("failed revoking certificate: %s", err)
			}

			response, err := getOCSPResponsePost(vaTest.HttpServerURL, crt, issuerCA)
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
	key, err := helpers.GenerateRSAKey(2048)
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %s", err)
	}

	csr, err := helpers.GenerateCertificateRequest(models.Subject{CommonName: "my-cert"}, key)
	if err != nil {
		return nil, fmt.Errorf("could not generate csr: %s", err)
	}

	crt, err := caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
		CAID:         DefaultCAID,
		CertRequest:  (*models.X509CertificateRequest)(csr),
		SignVerbatim: true,
	})
	if err != nil {
		return nil, fmt.Errorf("could not sign csr: %s", err)
	}

	return crt, nil
}

func getOCSPResponsePost(ocspServerURL string, crt *models.Certificate, issuer *models.CACertificate) (*ocsp.Response, error) {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest((*x509.Certificate)(crt.Certificate), (*x509.Certificate)(issuer.Certificate.Certificate), opts)
	if err != nil {
		return nil, fmt.Errorf("could not generate OCSP request: %s", err)
	}

	httpRequest, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/ocsp", ocspServerURL), bytes.NewBuffer(buffer))
	if err != nil {
		return nil, fmt.Errorf("could not generate HTTP OCSP request: %s", err)
	}
	ocspUrl, err := url.Parse(ocspServerURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse OCSP server URL: %s", err)
	}

	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspUrl.Host)

	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("could not DO OCSP request: %s", err)
	}

	defer httpResponse.Body.Close()
	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("could not decode OCSP response: %s", err)
	}

	response, err := ocsp.ParseResponse(output, (*x509.Certificate)(issuer.Certificate.Certificate))
	if err != nil {
		return nil, fmt.Errorf("could not parse OCSP response: %s", err)
	}

	return response, nil
}

func getOCSPResponseGet(ocspServerURL string, crt *models.Certificate, issuer *models.CACertificate) (*ocsp.Response, error) {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest((*x509.Certificate)(crt.Certificate), (*x509.Certificate)(issuer.Certificate.Certificate), opts)
	if err != nil {
		return nil, fmt.Errorf("could not generate OCSP request: %s", err)
	}

	encOCSPReq := url.QueryEscape(base64.StdEncoding.EncodeToString(buffer))

	httpRequest, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/ocsp/%s", ocspServerURL, encOCSPReq), bytes.NewBuffer(buffer))
	if err != nil {
		return nil, fmt.Errorf("could not generate HTTP OCSP request: %s", err)
	}
	ocspUrl, err := url.Parse(ocspServerURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse OCSP server URL: %s", err)
	}

	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspUrl.Host)

	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("could not DO OCSP request: %s", err)
	}

	defer httpResponse.Body.Close()
	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("could not decode OCSP response: %s", err)
	}

	response, err := ocsp.ParseResponse(output, (*x509.Certificate)(issuer.Certificate.Certificate))
	if err != nil {
		return nil, fmt.Errorf("could not parse OCSP response: %s", err)
	}

	return response, nil
}

type VATestServer struct {
	HttpServerURL string
	CaSDK         services.CAService
	BeforeEach    func() error
}

func BuildVATestServer(t *testing.T) (*VATestServer, error) {
	pConfig, postgresSuite := initPostgres([]string{"ca", "devicemanager"})

	caServer, err := buildCASimpleTestServer(pConfig, postgresSuite)
	if err != nil {
		return nil, fmt.Errorf("could not create CA test server: %s", err)
	}
	t.Cleanup(caServer.AfterSuite)

	_, _, port, err := AssembleVAServiceWithHTTPServer(config.VAconfig{
		BaseConfig: config.BaseConfig{
			Logs: config.BaseConfigLogging{
				Level: config.Info,
			},
			Server: config.HttpServer{
				LogLevel:           config.Info,
				HealthCheckLogging: false,
				Protocol:           config.HTTP,
			},
			EventBus: config.EventBusEngine{Enabled: false},
		},
		CAClient: config.CAClient{},
	}, caServer.HttpCASDK, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})
	if err != nil {
		return nil, err
	}

	//Init CA Server with 1 CA
	caDUr := models.TimeDuration(time.Hour * 24)
	issuanceDur := models.TimeDuration(time.Hour * 12)
	_, err = caServer.Service.CreateCA(context.Background(), services.CreateCAInput{
		ID:                 DefaultCAID,
		KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:            models.Subject{CommonName: "TestCA"},
		CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDUr},
		IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
	})
	if err != nil {
		return nil, err
	}

	return &VATestServer{
		HttpServerURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		CaSDK:         caServer.HttpCASDK,
		BeforeEach: func() error {
			err := caServer.BeforeEach()
			if err != nil {
				return fmt.Errorf("could not run CATestServer BeforeEach: %s", err)
			}
			return nil
		},
	}, nil
}

//Hacer la función de test de getCRL
