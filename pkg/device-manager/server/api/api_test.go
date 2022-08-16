package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/fullsailor/pkcs7"
	"github.com/gavv/httpexpect/v2"
	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	caService "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	dmsApi "github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"

	testUtils "github.com/lamassuiot/lamassuiot/pkg/utils/test"
)

type TestCase struct {
	name                  string
	useForgedDMS          bool
	serviceInitialization func(svc *service.Service, caSvc *caService.Service)
	testRestEndpoint      func(e *httpexpect.Expect)
}

func TestEnroll(t *testing.T) {
	tt := []TestCase{
		{
			name:                  "ShouldEnrollWhileCreatingNewDevice",
			useForgedDMS:          false,
			serviceInitialization: func(svc *service.Service, caSvc *caService.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequest("1234-5678-9012-3456")
				b := e.POST("/.well-known/est/RPI-CA/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(200).
					Body()

				pkcs7B64 := fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", b.Raw())
				pkcs7BER, _ := pem.Decode([]byte(pkcs7B64))
				pkcs7Certificate, err := pkcs7.Parse(pkcs7BER.Bytes)
				if err != nil {
					t.Errorf("Failed to parse certificate: %s", err)
				}

				certificate := pkcs7Certificate.Certificates[0]

				if certificate.Subject.CommonName != "1234-5678-9012-3456" {
					t.Errorf("Expected common name to be '1234-5678-9012-3456', got '%s'", certificate.Subject.CommonName)
				}
			},
		},
		{
			name:         "ShouldEnrollCreatingSlot",
			useForgedDMS: false,
			serviceInitialization: func(svc *service.Service, caSvc *caService.Service) {
				_, err := (*svc).CreateDevice(context.Background(), &api.CreateDeviceInput{
					DeviceID:    "1234-5678-9012-3456",
					Alias:       "Raspberry Pi",
					Tags:        []string{"raspberry-pi", "5G"},
					IconColor:   "",
					IconName:    "",
					Description: "Raspberry Pi is a small, low-cost, and light-weight computer",
				})
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequest("slot1:1234-5678-9012-3456")
				b := e.POST("/.well-known/est/RPI-CA/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(200).
					Body()

				pkcs7B64 := fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", b.Raw())
				pkcs7BER, _ := pem.Decode([]byte(pkcs7B64))
				pkcs7Certificate, err := pkcs7.Parse(pkcs7BER.Bytes)
				if err != nil {
					t.Errorf("Failed to parse certificate: %s", err)
				}

				certificate := pkcs7Certificate.Certificates[0]

				if certificate.Subject.CommonName != "slot1:1234-5678-9012-3456" {
					t.Errorf("Expected common name to be '1234-5678-9012-3456', got '%s'", certificate.Subject.CommonName)
				}
			},
		},
		{
			name:                  "MissingContentTypeHeader",
			useForgedDMS:          false,
			serviceInitialization: func(svc *service.Service, caSvc *caService.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequest("slot1:1234-5678-9012-3456")
				_ = e.POST("/.well-known/est/RPI-CA/simpleenroll").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(400)
			},
		},
		{
			name:                  "BadBodyPayload",
			useForgedDMS:          false,
			serviceInitialization: func(svc *service.Service, caSvc *caService.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.POST("/.well-known/est/RPI-CA-PROD/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte("slot1:aaaaa")).
					Expect().
					Status(400)
			},
		},
		{
			name:                  "UnauthorizedAPS",
			useForgedDMS:          false,
			serviceInitialization: func(svc *service.Service, caSvc *caService.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequest("slot1:1234-5678-9012-3456")
				_ = e.POST("/.well-known/est/RPI-CA-PROD/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(403)
			},
		},
		{
			name:                  "UnauthorizedAPS",
			useForgedDMS:          false,
			serviceInitialization: func(svc *service.Service, caSvc *caService.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequest("slot1:1234-5678-9012-3456")
				_ = e.POST("/.well-known/est/RPI-CA-PROD/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(403)
			},
		},
		{
			name:                  "InvalidCommonNameFormat",
			useForgedDMS:          false,
			serviceInitialization: func(svc *service.Service, caSvc *caService.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequest("slot1:1234-5678-9012-3456:something")
				_ = e.POST("/.well-known/est/RPI-CA/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(400)
			},
		},
		{
			name: "AllreadyEnrolledSlot",
			serviceInitialization: func(svc *service.Service, caSvc *caService.Service) {
				_, err := (*svc).CreateDevice(context.Background(), &api.CreateDeviceInput{
					DeviceID:    "1234-5678-9012-3456",
					Alias:       "Raspberry Pi",
					Tags:        []string{"raspberry-pi", "5G"},
					IconColor:   "",
					IconName:    "",
					Description: "Raspberry Pi is a small, low-cost, and light-weight computer",
				})
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				_, csr := generateCertificateRequest("slot1:1234-5678-9012-3456")
				singOutput, err := (*caSvc).SignCertificateRequest(context.Background(), &caApi.SignCertificateRequestInput{
					CAType:                    caApi.CATypePKI,
					CAName:                    "RPI-CA",
					CertificateSigningRequest: csr,
				})
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				_, err = (*svc).AddDeviceSlot(context.Background(), &api.AddDeviceSlotInput{
					DeviceID:          "1234-5678-9012-3456",
					SlotID:            "slot1",
					ActiveCertificate: singOutput.Certificate,
				})
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}
			},
			useForgedDMS: false,
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequest("slot1:1234-5678-9012-3456")
				_ = e.POST("/.well-known/est/RPI-CA/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(409).
					Body()
			},
		},
		{
			name:                  "ForgedDMSCertificate",
			serviceInitialization: func(svc *service.Service, caSvc *caService.Service) {},
			useForgedDMS:          true,
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequest("slot1:1234-5678-9012-3456")
				_ = e.POST("/.well-known/est/RPI-CA/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(403)
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			runTests(t, tc)
		})
	}
}

func runTests(t *testing.T, tc TestCase) {
	serverCA, svcCA, err := testUtils.BuildCATestServer()
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer serverCA.Close()
	serverCA.Start()

	_, err = (*svcCA).CreateCA(context.Background(), &caApi.CreateCAInput{
		CAType: caApi.CATypeDMSEnroller,
		Subject: caApi.Subject{
			CommonName: "LAMASSU-DMS-MANAGER",
		},
		KeyMetadata: caApi.KeyMetadata{
			KeyType: "RSA",
			KeyBits: 4096,
		},
		CADuration:       time.Hour * 24 * 365 * 5,
		IssuanceDuration: time.Hour * 24 * 365 * 3,
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	_, err = (*svcCA).CreateCA(context.Background(), &caApi.CreateCAInput{
		CAType: caApi.CATypePKI,
		Subject: caApi.Subject{
			CommonName: "RPI-CA",
		},
		KeyMetadata: caApi.KeyMetadata{
			KeyType: "RSA",
			KeyBits: 4096,
		},
		CADuration:       time.Hour * 24 * 365 * 5,
		IssuanceDuration: time.Hour * 24 * 365 * 3,
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	serverDMS, svcDMSanager, err := testUtils.BuildDMSManagerTestServer(serverCA)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer serverDMS.Close()
	serverDMS.Start()

	dmsOutput, err := (*svcDMSanager).CreateDMS(context.Background(), &dmsApi.CreateDMSInput{
		Subject: dmsApi.Subject{
			CommonName: "RPI-DMS",
		},
		KeyMetadata: dmsApi.KeyMetadata{
			KeyType: "RSA",
			KeyBits: 4096,
		},
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	dmsKey := dmsOutput.PrivateKey
	dmsKeyBits := x509.MarshalPKCS1PrivateKey(dmsKey.(*rsa.PrivateKey))
	dmsKeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: dmsKeyBits})

	dms, err := (*svcDMSanager).UpdateDMSStatus(context.Background(), &dmsApi.UpdateDMSStatusInput{
		Name:   "RPI-DMS",
		Status: dmsApi.DMSStatusApproved,
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	dmsCertBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dms.X509Asset.Certificate.Raw})

	_, err = (*svcDMSanager).UpdateDMSAuthorizedCAs(context.Background(), &dmsApi.UpdateDMSAuthorizedCAsInput{
		Name:          "RPI-DMS",
		AuthorizedCAs: []string{"RPI-CA"},
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	serverDeviceManager, svcDeviceManager, err := testUtils.BuildDeviceManagerTestServer(serverCA, serverDMS)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer serverDeviceManager.Close()
	serverDeviceManager.TLS = &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
	}
	serverDeviceManager.StartTLS()

	var tlsDMSCertificate tls.Certificate
	if tc.useForgedDMS {
		genKey, genCrt := generateCertificate("RPI-DMS")
		genCrtBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: genCrt.Raw})
		genKeyDer := x509.MarshalPKCS1PrivateKey(genKey)
		genKeyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: genKeyDer})
		tlsDMSCertificate, err = tls.X509KeyPair(genCrtBytes, genKeyBytes)
		if err != nil {
			t.Fatalf("%s", err)
		}
	} else {
		tlsDMSCertificate, err = tls.X509KeyPair(dmsCertBytes, dmsKeyPem)
		if err != nil {
			t.Fatalf("%s", err)
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{tlsDMSCertificate},
		},
	}

	httpClient := &http.Client{
		Transport: tr,
	}

	tc.serviceInitialization(svcDeviceManager, svcCA)
	e := httpexpect.WithConfig(httpexpect.Config{
		Reporter: t,
		BaseURL:  serverDeviceManager.URL,
		Client:   httpClient,
	})
	tc.testRestEndpoint(e)

}

func generateCertificate(commonName string) (*rsa.PrivateKey, *x509.Certificate) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}
	crtBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		panic(err)
	}

	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		panic(err)
	}

	return key, crt
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

func generateBase64EncodedCertificateRequest(commonName string) (*rsa.PrivateKey, string) {
	key, csr := generateCertificateRequest(commonName)

	csrBase64 := base64.StdEncoding.EncodeToString(csr.Raw)
	return key, csrBase64
}
