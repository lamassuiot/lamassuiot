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
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/fullsailor/pkcs7"
	"github.com/gavv/httpexpect/v2"
	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	caService "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	dmsApi "github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	estClient "github.com/lamassuiot/lamassuiot/pkg/est/client"
	"golang.org/x/exp/slices"

	testUtils "github.com/lamassuiot/lamassuiot/pkg/utils/test/utils"
)

type contextKey string

var (
	ContextKeyMTLSConfig  contextKey = "mTLSConfig"
	ContextKeyBaseAddress contextKey = "BaseAddress"
)

type mTLSConfig struct {
	useMTLS         bool
	mTLSCertificate *x509.Certificate
	mTLSRSAKey      *rsa.PrivateKey
}

type TestCase struct {
	name                  string
	serviceInitialization func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context
	testRestEndpoint      func(ctx context.Context, e *httpexpect.Expect)
}

func TestEnroll(t *testing.T) {
	tt := []TestCase{
		{
			name: "ShouldEnrollWhileCreatingNewDevice",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx

			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequestAndKey("1234-5678-9012-3456")
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
			name: "ShouldEnrollUsingHeaderXForwardedClientCertAuth",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequestAndKey("1234-5678-9012-3456")
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
			name: "ShouldEnrollCreatingSlot",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				// _, err := (*svc).CreateDevice(context.Background(), &api.CreateDeviceInput{
				// 	DeviceID:    "1234-5678-9012-3456",
				// 	Alias:       "Raspberry Pi",
				// 	Tags:        []string{"raspberry-pi", "5G"},
				// 	IconColor:   "",
				// 	IconName:    "",
				// 	Description: "Raspberry Pi is a small, low-cost, and light-weight computer",
				// })
				// if err != nil {
				// 	t.Fatalf("Failed to parse certificate: %s", err)
				// }

				return ctx

			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequestAndKey("slot1:1234-5678-9012-3456")
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
			name: "MissingContentTypeHeader",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequestAndKey("slot1:1234-5678-9012-3456")
				_ = e.POST("/.well-known/est/RPI-CA/simpleenroll").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(400)
			},
		},
		{
			name: "BadBodyPayload",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx

			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_ = e.POST("/.well-known/est/RPI-CA-PROD/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte("slot1:aaaaa")).
					Expect().
					Status(400)
			},
		},
		{
			name: "UnauthorizedAPS",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx

			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequestAndKey("slot1:1234-5678-9012-3456")
				_ = e.POST("/.well-known/est/RPI-CA-PROD/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(403)
			},
		},
		{
			name: "UnauthorizedAPS",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx

			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequestAndKey("slot1:1234-5678-9012-3456")
				_ = e.POST("/.well-known/est/RPI-CA-PROD/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(403)
			},
		},
		{
			name: "InvalidCommonNameFormat",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx

			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequestAndKey("slot1:1234-5678-9012-3456:something")
				_ = e.POST("/.well-known/est/RPI-CA/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(400)
			},
		},
		{
			name: "InvalidCommonNameFormat:ReservedKeyWord",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx

			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequestAndKey("default:1234-5678-9012-3456")
				_ = e.POST("/.well-known/est/RPI-CA/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(400)
			},
		},
		{
			name: "AllreadyEnrolledSlot",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
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

				_, csr := generateCertificateRequestAndKey("slot1:1234-5678-9012-3456")
				singOutput, err := (*caSvc).SignCertificateRequest(context.Background(), &caApi.SignCertificateRequestInput{
					CAType:                    caApi.CATypePKI,
					CAName:                    "RPI-CA",
					CertificateSigningRequest: csr,
					CommonName:                csr.Subject.CommonName,
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
				return ctx

			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequestAndKey("slot1:1234-5678-9012-3456")
				_ = e.POST("/.well-known/est/RPI-CA/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(409).
					Body()
			},
		},
		{
			name: "ForgedDMSCertificate",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				genKey, genCrt := generateCertificate("RPI-DMS", "LAMASSU-DMS-MANAGER")
				ctx = context.WithValue(ctx, ContextKeyMTLSConfig, mTLSConfig{
					useMTLS:         true,
					mTLSRSAKey:      genKey,
					mTLSCertificate: genCrt,
				})
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_, b64CSREncoded := generateBase64EncodedCertificateRequestAndKey("slot1:1234-5678-9012-3456")
				_ = e.POST("/.well-known/est/RPI-CA/simpleenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(403)
			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}

func TestReEnroll(t *testing.T) {
	tt := []TestCase{
		{
			name: "ShouldReEnrollUsingDefaultSlot",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				deviceID := "1234-5678-9012-3456"
				key, csr := generateCertificateRequestAndKey(deviceID)
				dmsMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				deviceCrt, err := (*svc).Enroll(ctx, csr, dmsMTLSConfig.mTLSCertificate, "RPI-CA")
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				ctx = context.WithValue(ctx, ContextKeyMTLSConfig, mTLSConfig{
					useMTLS:         true,
					mTLSRSAKey:      key,
					mTLSCertificate: deviceCrt,
				})

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				deviceID := "1234-5678-9012-3456"
				deviceMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				b64CSREncoded := generateBase64EncodedCertificateRequest(deviceID, deviceMTLSConfig.mTLSRSAKey)
				b := e.POST("/.well-known/est/ca/simplereenroll").
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

				if certificate.Subject.CommonName != deviceID {
					t.Errorf("Expected common name to be '%s', got '%s'", deviceID, certificate.Subject.CommonName)
				}
			},
		},
		{
			name: "ShouldReEnrollUsingCustomSlot",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				deviceID := "slot1:1234-5678-9012-3456"
				key, csr := generateCertificateRequestAndKey(deviceID)
				dmsMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				deviceCrt, err := (*svc).Enroll(ctx, csr, dmsMTLSConfig.mTLSCertificate, "RPI-CA")
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				ctx = context.WithValue(ctx, ContextKeyMTLSConfig, mTLSConfig{
					useMTLS:         true,
					mTLSRSAKey:      key,
					mTLSCertificate: deviceCrt,
				})

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				deviceID := "slot1:1234-5678-9012-3456"
				deviceMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				b64CSREncoded := generateBase64EncodedCertificateRequest(deviceID, deviceMTLSConfig.mTLSRSAKey)
				b := e.POST("/.well-known/est/ca/simplereenroll").
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

				if certificate.Subject.CommonName != deviceID {
					t.Errorf("Expected common name to be '%s', got '%s'", deviceID, certificate.Subject.CommonName)
				}
			},
		},
		{
			name: "ShouldReenrollUsingHeaderXForwardedClientCertAuth",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				deviceID := "slot1:1234-5678-9012-3456"
				key, csr := generateCertificateRequestAndKey(deviceID)
				dmsMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				deviceCrt, err := (*svc).Enroll(ctx, csr, dmsMTLSConfig.mTLSCertificate, "RPI-CA")
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				ctx = context.WithValue(ctx, ContextKeyMTLSConfig, mTLSConfig{
					useMTLS:         true,
					mTLSRSAKey:      key,
					mTLSCertificate: deviceCrt,
				})
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				deviceID := "slot1:1234-5678-9012-3456"
				deviceMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				b64CSREncoded := generateBase64EncodedCertificateRequest(deviceID, deviceMTLSConfig.mTLSRSAKey)
				cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: deviceMTLSConfig.mTLSCertificate.Raw}))
				params := url.Values{}
				params.Add("Cert", cert)

				b := e.POST("/.well-known/est/ca/simplereenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithHeader("X-Forwarded-Client-Cert", params.Encode()).
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(200).
					Body()

				pkcs7B64 := fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", b.Raw())
				pkcs7BER, _ := pem.Decode([]byte(pkcs7B64))
				pkcs7Certificate, err := pkcs7.Parse(pkcs7BER.Bytes)
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				certificate := pkcs7Certificate.Certificates[0]

				if certificate.Subject.CommonName != deviceID {
					t.Errorf("Expected common name to be '%s', got '%s'", deviceID, certificate.Subject.CommonName)
				}
			},
		},
		{
			name: "HonorMinimumReenrollmentDays",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				deviceID := "slot1:1234-5678-9012-3456"
				key, csr := generateCertificateRequestAndKey(deviceID)
				dmsMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				deviceCrt, err := (*svc).Enroll(ctx, csr, dmsMTLSConfig.mTLSCertificate, "RPI-CA-LONG")
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				ctx = context.WithValue(ctx, ContextKeyMTLSConfig, mTLSConfig{
					useMTLS:         true,
					mTLSRSAKey:      key,
					mTLSCertificate: deviceCrt,
				})

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				deviceID := "slot1:1234-5678-9012-3456"
				deviceMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				b64CSREncoded := generateBase64EncodedCertificateRequest(deviceID, deviceMTLSConfig.mTLSRSAKey)
				_ = e.POST("/.well-known/est/ca/simplereenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(403)

			},
		},
		{
			name: "MissmatchingCertificateRequestSubject",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				deviceID := "slot1:1234-5678-9012-3456"
				key, csr := generateCertificateRequestAndKey(deviceID)
				dmsMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				deviceCrt, err := (*svc).Enroll(ctx, csr, dmsMTLSConfig.mTLSCertificate, "RPI-CA")
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				ctx = context.WithValue(ctx, ContextKeyMTLSConfig, mTLSConfig{
					useMTLS:         true,
					mTLSRSAKey:      key,
					mTLSCertificate: deviceCrt,
				})

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				deviceID := "slot1:1234-5678-9012-3456"
				deviceMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				b64CSREncoded := generateBase64EncodedCertificateRequest(deviceID+"something", deviceMTLSConfig.mTLSRSAKey)
				_ = e.POST("/.well-known/est/ca/simplereenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(400)

			},
		},
		{
			name: "ExpiredCertificate",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				deviceID := "slot1:1234-5678-9012-3456"
				key, csr := generateCertificateRequestAndKey(deviceID)
				dmsMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				deviceCrt, err := (*svc).Enroll(ctx, csr, dmsMTLSConfig.mTLSCertificate, "RPI-CA-SHORT")
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				ctx = context.WithValue(ctx, ContextKeyMTLSConfig, mTLSConfig{
					useMTLS:         true,
					mTLSRSAKey:      key,
					mTLSCertificate: deviceCrt,
				})

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				deviceID := "slot1:1234-5678-9012-3456"
				deviceMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				b64CSREncoded := generateBase64EncodedCertificateRequest(deviceID, deviceMTLSConfig.mTLSRSAKey)

				time.Sleep(time.Second * 3)

				_ = e.POST("/.well-known/est/ca/simplereenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(403)

			},
		},
		{
			name: "RevokedCertificate",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				deviceID := "slot1:1234-5678-9012-3456"
				key, csr := generateCertificateRequestAndKey(deviceID)
				dmsMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				deviceCrt, err := (*svc).Enroll(ctx, csr, dmsMTLSConfig.mTLSCertificate, "RPI-CA")
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				ctx = context.WithValue(ctx, ContextKeyMTLSConfig, mTLSConfig{
					useMTLS:         true,
					mTLSRSAKey:      key,
					mTLSCertificate: deviceCrt,
				})

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				deviceID := "slot1:1234-5678-9012-3456"
				deviceMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				b64CSREncoded := generateBase64EncodedCertificateRequest(deviceID+"something", deviceMTLSConfig.mTLSRSAKey)
				_ = e.POST("/.well-known/est/ca/simplereenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(400)

			},
		},
		{
			name: "ForgedCredentials",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				deviceID := "slot1:1234-5678-9012-3456"
				_, csr := generateCertificateRequestAndKey(deviceID)
				dmsMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				_, err := (*svc).Enroll(ctx, csr, dmsMTLSConfig.mTLSCertificate, "RPI-CA")
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				forgedKey, forgedCrt := generateCertificate(deviceID, "RPI-CA")

				ctx = context.WithValue(ctx, ContextKeyMTLSConfig, mTLSConfig{
					useMTLS:         true,
					mTLSRSAKey:      forgedKey,
					mTLSCertificate: forgedCrt,
				})

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				deviceID := "slot1:1234-5678-9012-3456"
				deviceMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				b64CSREncoded := generateBase64EncodedCertificateRequest(deviceID, deviceMTLSConfig.mTLSRSAKey)
				_ = e.POST("/.well-known/est/ca/simplereenroll").
					WithHeader("Content-Type", "application/pkcs10").
					WithBytes([]byte(b64CSREncoded)).
					Expect().
					Status(403)

			},
		},
	}
	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}

func TestServerKeygen(t *testing.T) {
	tt := []TestCase{
		{
			name: "ShouldGenerateServerKey",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				deviceID := "1234-5678-9012-3456"

				baseAddress := ctx.Value(ContextKeyBaseAddress).(string)
				parsedUrl, err := url.Parse(baseAddress)
				if err != nil {
					t.Fatalf("Failed to parse base address: %s", err)
				}
				deviceMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				_, csr := generateCertificateRequestAndKey(deviceID)
				client, err := estClient.NewESTClient(nil, parsedUrl, deviceMTLSConfig.mTLSCertificate, deviceMTLSConfig.mTLSRSAKey, nil, true)
				if err != nil {
					t.Fatalf("Failed to create EST client: %s", err)
				}
				certificate, key, err := client.ServerKeyGen(ctx, "RPI-CA", csr)
				if err != nil {
					t.Fatalf("Failed to generate server key: %s", err)
				}

				if certificate.Subject.CommonName != deviceID {
					t.Errorf("Expected common name to be '%s', got '%s'", deviceID, certificate.Subject.CommonName)
				}

				if _, ok := key.(*rsa.PrivateKey); !ok {
					t.Errorf("Expected key to be of type *rsa.PrivateKey, got %T", key)
				}

			},
		},
		{
			name: "ShouldGenerateServerKeyUsingSlotID",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				deviceID := "slot1:1234-5678-9012-3456"

				baseAddress := ctx.Value(ContextKeyBaseAddress).(string)
				parsedUrl, err := url.Parse(baseAddress)
				if err != nil {
					t.Fatalf("Failed to parse base address: %s", err)
				}
				deviceMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				_, csr := generateCertificateRequestAndKey(deviceID)
				client, err := estClient.NewESTClient(nil, parsedUrl, deviceMTLSConfig.mTLSCertificate, deviceMTLSConfig.mTLSRSAKey, nil, true)
				if err != nil {
					t.Fatalf("Failed to create EST client: %s", err)
				}

				certificate, key, err := client.ServerKeyGen(ctx, "RPI-CA", csr)
				if err != nil {
					t.Fatalf("Failed to generate server key: %s", err)
				}

				if certificate.Subject.CommonName != deviceID {
					t.Errorf("Expected common name to be '%s', got '%s'", deviceID, certificate.Subject.CommonName)
				}

				if _, ok := key.(*rsa.PrivateKey); !ok {
					t.Errorf("Expected key to be of type *rsa.PrivateKey, got %T", key)
				}

			},
		},
		{
			name: "ShouldGenerateServerKeyUsingHeaderXForwardedClientCertAuth",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				deviceID := "slot1:1234-5678-9012-3456"

				baseAddress := ctx.Value(ContextKeyBaseAddress).(string)
				parsedUrl, err := url.Parse(baseAddress)
				if err != nil {
					t.Fatalf("Failed to parse base address: %s", err)
				}
				dmsMTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)
				_, csr := generateCertificateRequestAndKey(deviceID)
				client, err := estClient.NewESTClient(nil, parsedUrl, dmsMTLSConfig.mTLSCertificate, dmsMTLSConfig.mTLSRSAKey, nil, true)
				if err != nil {
					t.Fatalf("Failed to create EST client: %s", err)
				}

				ctx = context.WithValue(ctx, estClient.WithXForwardedClientCertHeader, dmsMTLSConfig.mTLSCertificate)

				certificate, key, err := client.ServerKeyGen(ctx, "RPI-CA", csr)
				if err != nil {
					t.Fatalf("Failed to generate server key: %s", err)
				}

				if certificate.Subject.CommonName != deviceID {
					t.Errorf("Expected common name to be '%s', got '%s'", deviceID, certificate.Subject.CommonName)
				}

				if _, ok := key.(*rsa.PrivateKey); !ok {
					t.Errorf("Expected key to be of type *rsa.PrivateKey, got %T", key)
				}

			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}

func TestGetESTCAs(t *testing.T) {
	tt := []TestCase{
		{
			name: "ShouldGetESTCAs",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {

				ctx = context.WithValue(ctx, ContextKeyMTLSConfig, mTLSConfig{
					useMTLS: false,
				})
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				resp := e.GET("/.well-known/est/cacerts").
					Expect().
					Status(200)

				decodedResponse, err := base64.StdEncoding.DecodeString(resp.Body().Raw())
				if err != nil {
					t.Fatalf("Failed to decode b64 response: %s", err)
				}

				p7, err := pkcs7.Parse(decodedResponse)
				if err != nil {
					t.Fatalf("Failed to parse response body: %s", err)
				}

				if len(p7.Certificates) != 3 {
					t.Errorf("Expected 3 certificates, got %d", len(p7.Certificates))
				}

				expectedCAs := []string{"RPI-CA", "RPI-CA-SHORT", "RPI-CA-LONG"}
				visitedCAs := make([]string, 0)
				for _, cert := range p7.Certificates {
					if !slices.Contains(expectedCAs, cert.Subject.CommonName) {
						t.Errorf("Unexpected common name in response: %s", cert.Subject.CommonName)
					} else {
						visitedCAs = append(visitedCAs, cert.Subject.CommonName)
					}
				}

				if len(visitedCAs) != 3 {
					t.Errorf("Expected 3 visited cas, got %d", len(p7.Certificates))
				}
			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}

func TestHealth(t *testing.T) {

	tt := []TestCase{
		{
			name: "CorrectHealth",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				obj := e.GET("/v1/health").
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("healthy")
			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}

func TestGetStats(t *testing.T) {

	tt := []TestCase{

		{
			name: "EmptyDevices",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				obj := e.GET("/v1/stats").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("stats")
				obj.Object().ContainsKey("scan_date")
			},
		}, {
			name: "DevicesWithCertificate",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
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
				_, csr := generateCertificateRequestAndKey("slot1:1234-5678-9012-3456")
				singOutput, err := (*caSvc).SignCertificateRequest(context.Background(), &caApi.SignCertificateRequestInput{
					CAType:                    caApi.CATypePKI,
					CAName:                    "RPI-CA",
					CertificateSigningRequest: csr,
					CommonName:                csr.Subject.CommonName,
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
					t.Fatalf("Failed to add slot : %s", err)
				}

				return ctx

			},

			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				obj := e.GET("/v1/stats").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("stats")
				obj.Object().ContainsKey("scan_date")
			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}

func TestGetDeviceById(t *testing.T) {

	tt := []TestCase{

		{
			name: "GetDeviceById: NoSlots",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				_, err := (*svc).CreateDevice(context.Background(), &api.CreateDeviceInput{
					DeviceID:    "1234-5678-9012-3456",
					Alias:       "Raspberry Pi",
					Tags:        []string{"raspberry-pi", "5G"},
					IconColor:   "#0068D1",
					IconName:    "Cg/CgSmartphoneChip",
					Description: "Raspberry Pi is a small, low-cost, and light-weight computer",
				})
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				obj := e.GET("/v1/devices/1234-5678-9012-3456").
					Expect().
					Status(http.StatusOK).JSON().Object()

				obj.ContainsKey("id")
				obj.ContainsKey("alias")
				obj.ContainsKey("status")
				obj.ContainsKey("slots")
				obj.ContainsKey("description")
				obj.ContainsKey("tags")
				obj.ContainsKey("icon_name")
				obj.ContainsKey("icon_color")
				obj.ContainsKey("creation_timestamp")

			},
		},
		{
			name: "GetDeviceById: WithSlots",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				_, err := (*svc).CreateDevice(context.Background(), &api.CreateDeviceInput{
					DeviceID:    "1234-5678-9012-3456",
					Alias:       "Raspberry Pi",
					Tags:        []string{"raspberry-pi", "5G"},
					IconColor:   "#0068D1",
					IconName:    "Cg/CgSmartphoneChip",
					Description: "Raspberry Pi is a small, low-cost, and light-weight computer",
				})
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}
				_, csr := generateCertificateRequestAndKey("slot1:1234-5678-9012-3456")
				singOutput, err := (*caSvc).SignCertificateRequest(context.Background(), &caApi.SignCertificateRequestInput{
					CAType:                    caApi.CATypePKI,
					CAName:                    "RPI-CA",
					CertificateSigningRequest: csr,
					CommonName:                csr.Subject.CommonName,
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

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				obj := e.GET("/v1/devices/1234-5678-9012-3456").
					Expect().
					Status(http.StatusOK).JSON().Object()

				obj.ContainsKey("id")
				obj.ContainsKey("alias")
				obj.ContainsKey("status")
				obj.ContainsKey("slots")
				obj.ContainsKey("description")
				obj.ContainsKey("tags")
				obj.ContainsKey("icon_name")
				obj.ContainsKey("icon_color")
				obj.ContainsKey("creation_timestamp")

			},
		},
		{
			name: "GetDeviceById_Error",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				e.GET("/v1/devices/error").
					Expect().
					Status(http.StatusNotFound)
			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}

func TestGetDevices(t *testing.T) {
	tt := []TestCase{
		{
			name: "GetDevices:EmptyList",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				obj := e.GET("/v1/devices").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_devices").ValueEqual("total_devices", 0)
				obj.Object().ContainsKey("devices")

				obj.Object().Value("devices").Array().Empty()
			},
		},
		{
			name: "GetDevices:OneDevice",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
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
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				resp := e.GET("/v1/devices").
					Expect().
					Status(http.StatusOK).JSON()

				resp.Object().Value("devices").Array().Length().Equal(1)

			},
		},
		{
			name: "GetDevices:3Devices",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				for i := 1; i < 4; i++ {
					_, err := (*svc).CreateDevice(context.Background(), &api.CreateDeviceInput{
						DeviceID:    "device-" + strconv.Itoa(i),
						Alias:       "Raspberry Pi",
						Tags:        []string{"raspberry-pi", "5G"},
						IconColor:   "",
						IconName:    "",
						Description: "Raspberry Pi is a small, low-cost, and light-weight computer",
					})
					if err != nil {
						t.Fatalf("Failed to parse certificate: %s", err)
					}
				}

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				resp := e.GET("/v1/devices").
					Expect().
					Status(http.StatusOK).JSON()

				resp.Object().Value("devices").Array().Length().Equal(3)

			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}

func TestUpdateDeviceMetadata(t *testing.T) {
	tt := []TestCase{

		{
			name: "NoDevice",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBytes := `{"alias":"Raspberry", "tags": ["raspberry-pi"], "description": "Raspberry Pi is a small", "icon_color":"#0068D1", "icon_name": "Cg/CgSmartphoneChip"}`
				e.PUT("/v1/devices/error").WithBytes([]byte(reqBytes)).
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "UpdateDevice_JSONError",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				device := `"badRequest":"1"}`

				e.PUT("/v1/devices/deviceID").WithBytes([]byte(device)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "UpdateDeviceMetadata",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				_, err := (*svc).CreateDevice(context.Background(), &api.CreateDeviceInput{
					DeviceID:    "1234-5678-9012-3456",
					Alias:       "Raspberry Pi",
					Tags:        []string{"raspberry-pi", "5G"},
					IconColor:   "#0068D1",
					IconName:    "Cg/CgSmartphoneChip",
					Description: "Raspberry Pi is a small, low-cost, and light-weight computer",
				})
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBytes := `{"device_id":"1234", "alias":"Raspberry", "tags": ["raspberry-pi"], "description": "Raspberry Pi is a small", "icon_color":"#0068D1", "icon_name": "Cg/CgSmartphoneChip"}`

				obj := e.PUT("/v1/devices/1234-5678-9012-3456").WithBytes([]byte(reqBytes)).
					Expect().
					Status(http.StatusOK).JSON().Object()

				obj.ContainsKey("slots")
				obj.ContainsKey("creation_timestamp")

				obj.ContainsMap(map[string]interface{}{
					"alias":       "Raspberry",
					"id":          "1234-5678-9012-3456",
					"status":      api.DeviceStatusPendingProvisioning,
					"description": "Raspberry Pi is a small",
					"tags":        []string{"raspberry-pi"},
					"icon_color":  "#0068D1",
					"icon_name":   "Cg/CgSmartphoneChip",
				})

			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}

func TestDecommisionDevice(t *testing.T) {
	tt := []TestCase{

		{
			name: "NoDevice",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				e.DELETE("/v1/devices/error").
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "DecommisionDevice",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				_, err := (*svc).CreateDevice(context.Background(), &api.CreateDeviceInput{
					DeviceID:    "1234-5678-9012-3456",
					Alias:       "Raspberry Pi",
					Tags:        []string{"raspberry-pi", "5G"},
					IconColor:   "#0068D1",
					IconName:    "Cg/CgSmartphoneChip",
					Description: "Raspberry Pi is a small, low-cost, and light-weight computer",
				})
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {

				obj := e.DELETE("/v1/devices/1234-5678-9012-3456").
					Expect().
					Status(http.StatusOK).JSON().Object()

				obj.ContainsKey("id")
				obj.ContainsKey("alias")
				obj.ContainsKey("status")
				obj.ContainsKey("slots")
				obj.ContainsKey("description")
				obj.ContainsKey("tags")
				obj.ContainsKey("icon_name")
				obj.ContainsKey("icon_color")
				obj.ContainsKey("creation_timestamp")

			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}

func TestRevokeActiveCertificate(t *testing.T) {
	tt := []TestCase{

		{
			name: "NoDevice",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBytes := `{"revocation_reason":"Device"}`
				e.DELETE("/v1/devices/device/slots/slot").WithBytes([]byte(reqBytes)).
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "NoSlot",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				_, err := (*svc).CreateDevice(context.Background(), &api.CreateDeviceInput{
					DeviceID:    "1234-5678-9012-3456",
					Alias:       "Raspberry Pi",
					Tags:        []string{"raspberry-pi", "5G"},
					IconColor:   "#0068D1",
					IconName:    "Cg/CgSmartphoneChip",
					Description: "Raspberry Pi is a small, low-cost, and light-weight computer",
				})
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBytes := `{"revocation_reason":"Device"}`
				e.DELETE("/v1/devices/1234-5678-9012-3456/slots/slot").WithBytes([]byte(reqBytes)).
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "RevokeNonActiveCertificate",

			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				_, err := (*svc).CreateDevice(context.Background(), &api.CreateDeviceInput{
					DeviceID:    "1234-5678-9012-3456",
					Alias:       "Raspberry Pi",
					Tags:        []string{"raspberry-pi", "5G"},
					IconColor:   "#0068D1",
					IconName:    "Cg/CgSmartphoneChip",
					Description: "Raspberry Pi is a small, low-cost, and light-weight computer",
				})
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {

				obj := e.DELETE("/v1/devices/1234-5678-9012-3456").
					Expect().
					Status(http.StatusOK).JSON().Object()

				obj.ContainsKey("slots")
				obj.ContainsKey("creation_timestamp")

				obj.ContainsMap(map[string]interface{}{
					"alias":       "Raspberry Pi",
					"id":          "1234-5678-9012-3456",
					"status":      api.DeviceStatusDecommissioned,
					"description": "Raspberry Pi is a small, low-cost, and light-weight computer",
					"tags":        []string{"raspberry-pi", "5G"},
					"icon_color":  "#0068D1",
					"icon_name":   "Cg/CgSmartphoneChip",
				})

			},
		},
		{
			name: "RevokeActiveCertificate",

			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				_, err := (*svc).CreateDevice(context.Background(), &api.CreateDeviceInput{
					DeviceID:    "1234-5678-9012-3456",
					Alias:       "Raspberry Pi",
					Tags:        []string{"raspberry-pi", "5G"},
					IconColor:   "#0068D1",
					IconName:    "Cg/CgSmartphoneChip",
					Description: "Raspberry Pi is a small, low-cost, and light-weight computer",
				})
				if err != nil {
					t.Fatalf("Failed to parse certificate: %s", err)
				}
				_, csr := generateCertificateRequestAndKey("slot1:1234-5678-9012-3456")
				singOutput, err := (*caSvc).SignCertificateRequest(context.Background(), &caApi.SignCertificateRequestInput{
					CAType:                    caApi.CATypePKI,
					CAName:                    "RPI-CA-LONG",
					CertificateSigningRequest: csr,
					CommonName:                csr.Subject.CommonName,
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

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {

				obj := e.DELETE("/v1/devices/1234-5678-9012-3456").
					Expect().
					Status(http.StatusOK).JSON().Object()

				obj.ContainsKey("slots")
				obj.ContainsKey("creation_timestamp")

				obj.ContainsMap(map[string]interface{}{
					"alias":       "Raspberry Pi",
					"id":          "1234-5678-9012-3456",
					"status":      api.DeviceStatusDecommissioned,
					"description": "Raspberry Pi is a small, low-cost, and light-weight computer",
					"tags":        []string{"raspberry-pi", "5G"},
					"icon_color":  "#0068D1",
					"icon_name":   "Cg/CgSmartphoneChip",
				})

			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}
func TestGetDeviceLogs(t *testing.T) {
	tt := []TestCase{

		{
			name: "NoDevice",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				e.GET("/v1/devices/error/logs").
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "GetLogs: NoSlot",
			serviceInitialization: func(ctx context.Context, svc *service.Service, caSvc *caService.Service) context.Context {
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
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				resp := e.GET("/v1/devices/1234-5678-9012-3456/logs").
					Expect().
					Status(http.StatusOK).JSON().Object()

				resp.ContainsKey("slot_logs")
				resp.ContainsKey("logs")
				resp.ContainsMap(map[string]interface{}{
					"device_id": "1234-5678-9012-3456",
				})

			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTests(t, tc)
		})
	}
}

func runTests(t *testing.T, tc TestCase) {
	ctx := context.Background()
	serverCA, svcCA, err := testUtils.BuildCATestServer()
	//cli, err := testUtils.NewVaultSecretsMock(t)
	//if err != nil {
	//	t.Errorf("%s", err)
	//}
	//server, svc, err := testUtils.BuildCATestServerWithVault(cli)

	if err != nil {
		t.Fatalf("%s", err)
	}
	defer serverCA.Close()
	serverCA.Start()

	/*_, err = (*svcCA).CreateCA(context.Background(), &caApi.CreateCAInput{
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
	}*/

	_, err = (*svcCA).CreateCA(context.Background(), &caApi.CreateCAInput{
		CAType: caApi.CATypePKI,
		Subject: caApi.Subject{
			CommonName: "RPI-CA",
		},
		KeyMetadata: caApi.KeyMetadata{
			KeyType: "RSA",
			KeyBits: 4096,
		},
		CAExpiration:       time.Now().Add(time.Hour * 24 * 365 * 5),
		IssuanceExpiration: time.Now().Add(time.Hour * 24 * 25),
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	_, err = (*svcCA).CreateCA(context.Background(), &caApi.CreateCAInput{
		CAType: caApi.CATypePKI,
		Subject: caApi.Subject{
			CommonName: "RPI-CA-LONG",
		},
		KeyMetadata: caApi.KeyMetadata{
			KeyType: "RSA",
			KeyBits: 4096,
		},
		CAExpiration:       time.Now().Add(time.Hour * 24 * 365 * 5),
		IssuanceExpiration: time.Now().Add(time.Hour * 24 * 365 * 3),
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	_, err = (*svcCA).CreateCA(context.Background(), &caApi.CreateCAInput{
		CAType: caApi.CATypePKI,
		Subject: caApi.Subject{
			CommonName: "RPI-CA-SHORT",
		},
		KeyMetadata: caApi.KeyMetadata{
			KeyType: "RSA",
			KeyBits: 4096,
		},
		CAExpiration:       time.Now().Add(time.Hour * 24 * 365 * 5),
		IssuanceExpiration: time.Now().Add(time.Hour * 3),
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

	dmsOutput, err := (svcDMSanager).CreateDMS(context.Background(), &dmsApi.CreateDMSInput{
		DeviceManufacturingService: dmsApi.DeviceManufacturingService{
			Name:     "RPI-DMS",
			CloudDMS: false,
			RemoteAccessIdentity: &dmsApi.RemoteAccessIdentity{
				ExternalKeyGeneration: false,
				KeyMetadata: dmsApi.KeyStrengthMetadata{
					KeyType: dmsApi.RSA,
					KeyBits: 2048,
				},
				Subject: dmsApi.Subject{
					CommonName: "RPI-DMS",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	dmsKey := dmsOutput.PrivateKey

	dms, err := (svcDMSanager).UpdateDMSStatus(context.Background(), &dmsApi.UpdateDMSStatusInput{
		Name:   "RPI-DMS",
		Status: dmsApi.DMSStatusApproved,
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	ctx = context.WithValue(ctx, ContextKeyMTLSConfig, mTLSConfig{
		useMTLS:         true,
		mTLSRSAKey:      dmsKey.(*rsa.PrivateKey),
		mTLSCertificate: dms.RemoteAccessIdentity.Certificate,
	})

	_, err = (svcDMSanager).UpdateDMSAuthorizedCAs(context.Background(), &dmsApi.UpdateDMSAuthorizedCAsInput{
		Name:          "RPI-DMS",
		AuthorizedCAs: []string{"RPI-CA", "RPI-CA-LONG", "RPI-CA-SHORT"},
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	serverDeviceManager, svcDeviceManager, err := testUtils.BuildDeviceManagerTestServer(serverCA, serverDMS)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer serverDeviceManager.Close()

	ctx = tc.serviceInitialization(ctx, svcDeviceManager, svcCA)
	mTLSConfig := ctx.Value(ContextKeyMTLSConfig).(mTLSConfig)

	httpClient := http.DefaultClient
	if mTLSConfig.useMTLS {
		serverDeviceManager.TLS = &tls.Config{
			ClientAuth: tls.RequireAnyClientCert,
		}

		serverDeviceManager.StartTLS()
		var tlsDMSCertificate tls.Certificate
		if mTLSConfig.mTLSCertificate == nil {
			t.Fatalf("mTLSCertificate is nil")
		}
		if mTLSConfig.mTLSRSAKey == nil {
			t.Fatalf("mTLSRSAKey is nil")
		}

		genCrtBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mTLSConfig.mTLSCertificate.Raw})
		genKeyDer := x509.MarshalPKCS1PrivateKey(mTLSConfig.mTLSRSAKey)
		genKeyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: genKeyDer})
		tlsDMSCertificate, err = tls.X509KeyPair(genCrtBytes, genKeyBytes)
		if err != nil {
			t.Fatalf("%s", err)
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{tlsDMSCertificate},
			},
		}

		httpClient = &http.Client{
			Transport: tr,
		}

	} else {
		serverDeviceManager.Start()
	}

	ctx = context.WithValue(ctx, ContextKeyBaseAddress, serverDeviceManager.URL)
	e := httpexpect.WithConfig(httpexpect.Config{
		Reporter: t,
		BaseURL:  serverDeviceManager.URL,
		Client:   httpClient,
	})
	tc.testRestEndpoint(ctx, e)
}

func generateCertificate(commonName string, issuerCommonName string) (*rsa.PrivateKey, *x509.Certificate) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"ES"},
			Locality:     []string{"Donostia"},
			Organization: []string{"LAMASSU Foundation"},
			CommonName:   commonName,
		},
	}

	issuerTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"ES"},
			Locality:     []string{"Donostia"},
			Organization: []string{"LAMASSU Foundation"},
			CommonName:   issuerCommonName,
		},
	}
	crtBytes, err := x509.CreateCertificate(rand.Reader, &template, &issuerTemplate, key.Public(), key)
	if err != nil {
		panic(err)
	}

	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		panic(err)
	}

	return key, crt
}

func generateCertificateRequestAndKey(commonName string) (*rsa.PrivateKey, *x509.CertificateRequest) {

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr := generateCertificateRequest(commonName, key)
	return key, csr
}

func generateCertificateRequest(commonName string, key *rsa.PrivateKey) *x509.CertificateRequest {

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

	return csr
}

func generateBase64EncodedCertificateRequest(commonName string, key *rsa.PrivateKey) string {
	csr := generateCertificateRequest(commonName, key)
	csrBase64 := base64.StdEncoding.EncodeToString(csr.Raw)
	return csrBase64
}

func generateBase64EncodedCertificateRequestAndKey(commonName string) (*rsa.PrivateKey, string) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr := generateCertificateRequest(commonName, key)
	csrBase64 := base64.StdEncoding.EncodeToString(csr.Raw)
	return key, csrBase64
}
