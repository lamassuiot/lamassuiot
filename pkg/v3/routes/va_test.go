package routes

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

func TestCRL(t *testing.T) {
	var testcases = []struct {
		name        string
		before      func(services.CAService) ([]*models.Certificate, error)
		resultCheck func(certs []*models.Certificate, issuer *models.CACertificate, crl *x509.RevocationList, err error) error
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
			resultCheck: func(crts []*models.Certificate, issuer *models.CACertificate, crl *x509.RevocationList, err error) error {
				if len(crl.RevokedCertificateEntries) != len(crts) {
					t.Fatalf("crl should have %d entries, got %d", len(crts), len(crl.RevokedCertificateEntries))
				}

				return nil
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
			resultCheck: func(crts []*models.Certificate, issuer *models.CACertificate, crl *x509.RevocationList, err error) error {
				if err != nil {
					return fmt.Errorf("should've got CRL, but got error: %s", err)
				}

				if err = crl.CheckSignatureFrom((*x509.Certificate)(issuer.Certificate.Certificate)); err != nil {
					t.Fatalf("invalid CRL signature: %s", err)
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			vaTest, err := BuildVATestServer()
			if err != nil {
				t.Fatalf("could not create VA test server")
			}
			vaTest.HttpServer.Start()

			issuerCA, err := vaTest.CaSDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
			if err != nil {
				t.Fatalf("could not get issuer CA: %s", err)
			}

			crts, err := tc.before(vaTest.CaSDK)
			if err != nil {
				t.Fatalf("could not run 'before' function:  %s", err)
			}

			httpRequest, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/crl/%s", vaTest.HttpServer.URL, DefaultCAID), nil)
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
			err = tc.resultCheck(crts, issuerCA, crl, err)
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
			vaTest, err := BuildVATestServer()
			if err != nil {
				t.Fatalf("could not create VA test server")
			}
			vaTest.HttpServer.Start()

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

			response, err := getOCSPResponsePost(vaTest.HttpServer.URL, crt, issuerCA)

			err = tc.resultCheck(crt, issuerCA, response, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}
func TestGetOCSP(t *testing.T) {
	vaTest, err := BuildVATestServer()
	if err != nil {
		t.Fatalf("could not create VA test server")
	}

	vaTest.HttpServer.Start()

	issuerCA, err := vaTest.CaSDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
	if err != nil {
		t.Fatalf("could not get issuer CA: %s", err)
	}

	crt, err := generateCertificate(vaTest.CaSDK)
	if err != nil {
		t.Fatalf("failed generating crt in test case: %s", err)
	}

	response, err := getOCSPResponseGet(vaTest.HttpServer.URL, crt, issuerCA)
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

	vaTest, err := BuildVATestServer()
	if err != nil {
		t.Fatalf("could not create VA test server")
	}
	vaTest.HttpServer.Start()

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

			response, err := getOCSPResponsePost(vaTest.HttpServer.URL, crt, issuerCA)
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
	OcspService services.OCSPService
	CrlService  services.CRLService
	HttpServer  *httptest.Server

	CaSDK services.CAService
}

func BuildVATestServer() (*VATestServer, error) {
	caServer, err := BuildCATestServer()
	if err != nil {
		return nil, fmt.Errorf("could not create CA test server: %s", err)
	}

	caServer.HttpServer.Start()
	caSDK := clients.NewHttpCAClient(http.DefaultClient, caServer.HttpServer.URL)

	lgr := logrus.StandardLogger().WithField("", "")
	ocspService := services.NewOCSPService(services.OCSPServiceBuilder{
		Logger:   lgr,
		CAClient: caSDK,
	})
	crlService := services.NewCRLService(services.CRLServiceBuilder{
		Logger:   lgr,
		CAClient: caSDK,
	})

	engine := NewGinEngine(lgr)
	httpGrp := engine.Group("/")
	NewValidationRoutes(lgr, httpGrp, ocspService, crlService)
	vaServer := httptest.NewUnstartedServer(engine)

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
		OcspService: ocspService,
		CrlService:  crlService,
		HttpServer:  vaServer,
		CaSDK:       caSDK,
	}, nil
}
