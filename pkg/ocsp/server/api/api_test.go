package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gavv/httpexpect/v2"
	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	caService "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"golang.org/x/crypto/ocsp"

	testUtils "github.com/lamassuiot/lamassuiot/pkg/utils/test/utils"
)

type TestCase struct {
	name                  string
	serviceInitialization func(ctx context.Context, caSvc *caService.Service) context.Context
	testRestEndpoint      func(ctx context.Context, e *httpexpect.Expect)
}

type contextKey string

var (
	OCSPResponderCertificate contextKey = "OCSPResponderCertificate"
	CACertificate            contextKey = "CACertificate"
	Certificate              contextKey = "Certificate"
)

func TestOCSPVerify(t *testing.T) {
	tt := []TestCase{
		{
			name: "OCSPVerifyGet",
			serviceInitialization: func(ctx context.Context, caSvc *caService.Service) context.Context {
				_, err := (*caSvc).CreateCA(context.Background(), &caApi.CreateCAInput{
					CAType: caApi.CATypePKI,
					Subject: caApi.Subject{
						CommonName: "RPI-CA",
					},
					KeyMetadata: caApi.KeyMetadata{
						KeyType: "RSA",
						KeyBits: 4096,
					},
					CADuration:       time.Hour * 24 * 365 * 5,
					IssuanceDuration: time.Hour * 24 * 25,
				})
				if err != nil {
					t.Fatalf("%s", err)
				}

				_, csr := generateCertificateRequest("test-cn")

				signOutput, err := (*caSvc).SignCertificateRequest(ctx, &caApi.SignCertificateRequestInput{
					CAType:                    caApi.CATypePKI,
					CAName:                    "RPI-CA",
					SignVerbatim:              true,
					CertificateSigningRequest: csr,
				})
				if err != nil {
					t.Fatalf("%s", err)
				}

				ctx = context.WithValue(ctx, Certificate, signOutput.Certificate)
				ctx = context.WithValue(ctx, CACertificate, signOutput.CACertificate)
				return ctx
			},

			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				certificate := ctx.Value(Certificate).(*x509.Certificate)
				caCertificate := ctx.Value(CACertificate).(*x509.Certificate)
				responderCertificate := ctx.Value(OCSPResponderCertificate).(*x509.Certificate)

				ocspReqBytes, err := ocsp.CreateRequest(certificate, caCertificate, nil)
				if err != nil {
					t.Fatalf("%s", err)
				}

				b64OcspReq := base64.StdEncoding.EncodeToString(ocspReqBytes)
				urlB64OcspReq := url.PathEscape(b64OcspReq)

				resp := e.GET("/" + urlB64OcspReq).
					Expect().
					Status(http.StatusOK).
					Body()

				rawOcspResponse := resp.Raw()
				ocspResponse, err := ocsp.ParseResponse([]byte(rawOcspResponse), responderCertificate)
				if err != nil {
					t.Fatalf("%s", err)
				}

				if ocspResponse.Status != ocsp.Good {
					t.Fatalf("OCSP response status is not good")
				}

			},
		},
		{
			name: "OCSPVerifyPostGood",
			serviceInitialization: func(ctx context.Context, caSvc *caService.Service) context.Context {
				_, err := (*caSvc).CreateCA(context.Background(), &caApi.CreateCAInput{
					CAType: caApi.CATypePKI,
					Subject: caApi.Subject{
						CommonName: "RPI-CA",
					},
					KeyMetadata: caApi.KeyMetadata{
						KeyType: "RSA",
						KeyBits: 4096,
					},
					CADuration:       time.Hour * 24 * 365 * 5,
					IssuanceDuration: time.Hour * 24 * 25,
				})
				if err != nil {
					t.Fatalf("%s", err)
				}

				_, csr := generateCertificateRequest("test-cn")

				signOutput, err := (*caSvc).SignCertificateRequest(ctx, &caApi.SignCertificateRequestInput{
					CAType:                    caApi.CATypePKI,
					CAName:                    "RPI-CA",
					SignVerbatim:              true,
					CertificateSigningRequest: csr,
				})
				if err != nil {
					t.Fatalf("%s", err)
				}

				ctx = context.WithValue(ctx, Certificate, signOutput.Certificate)
				ctx = context.WithValue(ctx, CACertificate, signOutput.CACertificate)
				return ctx
			},

			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				certificate := ctx.Value(Certificate).(*x509.Certificate)
				caCertificate := ctx.Value(CACertificate).(*x509.Certificate)
				responderCertificate := ctx.Value(OCSPResponderCertificate).(*x509.Certificate)

				ocspReqBytes, err := ocsp.CreateRequest(certificate, caCertificate, nil)
				if err != nil {
					t.Fatalf("%s", err)
				}

				resp := e.POST("/").
					WithBytes(ocspReqBytes).
					WithHeader("Content-Type", "application/ocsp-request").
					Expect().
					Status(http.StatusOK).
					Body()

				rawOcspResponse := resp.Raw()
				ocspResponse, err := ocsp.ParseResponse([]byte(rawOcspResponse), responderCertificate)
				if err != nil {
					t.Fatalf("%s", err)
				}

				if ocspResponse.Status != ocsp.Good {
					t.Fatalf("OCSP response status is not good")
				}

			},
		},
		{
			name: "OCSPVerifyPostRevoked",
			serviceInitialization: func(ctx context.Context, caSvc *caService.Service) context.Context {
				_, err := (*caSvc).CreateCA(context.Background(), &caApi.CreateCAInput{
					CAType: caApi.CATypePKI,
					Subject: caApi.Subject{
						CommonName: "RPI-CA",
					},
					KeyMetadata: caApi.KeyMetadata{
						KeyType: "RSA",
						KeyBits: 4096,
					},
					CADuration:       time.Hour * 24 * 365 * 5,
					IssuanceDuration: time.Hour * 24 * 25,
				})
				if err != nil {
					t.Fatalf("%s", err)
				}

				_, csr := generateCertificateRequest("test-cn")

				signOutput, err := (*caSvc).SignCertificateRequest(ctx, &caApi.SignCertificateRequestInput{
					CAType:                    caApi.CATypePKI,
					CAName:                    "RPI-CA",
					SignVerbatim:              true,
					CertificateSigningRequest: csr,
				})
				if err != nil {
					t.Fatalf("%s", err)
				}

				_, err = (*caSvc).RevokeCertificate(ctx, &caApi.RevokeCertificateInput{
					CAType:                  caApi.CATypePKI,
					CAName:                  "RPI-CA",
					CertificateSerialNumber: utils.InsertNth(utils.ToHexInt(signOutput.Certificate.SerialNumber), 2),
					RevocationReason:        "unspecified",
				})
				if err != nil {
					t.Fatalf("%s", err)
				}

				ctx = context.WithValue(ctx, Certificate, signOutput.Certificate)
				ctx = context.WithValue(ctx, CACertificate, signOutput.CACertificate)
				return ctx
			},

			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				certificate := ctx.Value(Certificate).(*x509.Certificate)
				caCertificate := ctx.Value(CACertificate).(*x509.Certificate)
				responderCertificate := ctx.Value(OCSPResponderCertificate).(*x509.Certificate)

				ocspReqBytes, err := ocsp.CreateRequest(certificate, caCertificate, nil)
				if err != nil {
					t.Fatalf("%s", err)
				}

				resp := e.POST("/").
					WithBytes(ocspReqBytes).
					WithHeader("Content-Type", "application/ocsp-request").
					Expect().
					Status(http.StatusOK).
					Body()

				rawOcspResponse := resp.Raw()
				ocspResponse, err := ocsp.ParseResponse([]byte(rawOcspResponse), responderCertificate)
				if err != nil {
					t.Fatalf("%s", err)
				}

				if ocspResponse.Status != ocsp.Revoked {
					t.Fatalf("OCSP response status is not revoked")
				}

			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			serverCA, svcCA, err := testUtils.BuildCATestServer()
			if err != nil {
				t.Fatalf("%s", err)
			}

			defer serverCA.Close()
			serverCA.Start()

			serverOCSP, err := testUtils.BuildOCSPTestServer(serverCA)
			if err != nil {
				t.Fatalf("%s", err)
			}

			defer serverOCSP.Close()
			serverOCSP.StartTLS()

			if len(serverOCSP.TLS.Certificates) != 1 {
				t.Fatalf("Expected 1 certificate in the server's TLS config")
			}

			ctx = context.WithValue(ctx, OCSPResponderCertificate, serverOCSP.TLS.Certificates[0].Leaf)

			ctx = tc.serviceInitialization(ctx, svcCA)
			e := httpexpect.WithConfig(httpexpect.Config{
				Reporter: t,
				BaseURL:  serverOCSP.URL,
				Client: &http.Client{Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				}},
			})
			tc.testRestEndpoint(ctx, e)
		})
	}
}

func generateCertificateRequest(commonName string) (*rsa.PrivateKey, *x509.CertificateRequest) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		panic(err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		panic(err)
	}

	return key, csr
}
