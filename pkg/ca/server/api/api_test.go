package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gavv/httpexpect/v2"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	testUtils "github.com/lamassuiot/lamassuiot/pkg/utils/test/utils"
)

func TestCreateCA(t *testing.T) {
	tt := []struct {
		name                  string
		serviceInitialization func(svc *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name:                  "ShouldCreateCA",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"subject":{"common_name": "ca-name-1"},"key_metadata":{"type": "RSA", "bits": 2048},"ca_expiration": "9000", "issuance_expiration": "1000", "expiration_type":"DURATION" }`
				obj := e.POST("/v1/pki").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsMap(map[string]interface{}{
					"key_metadata": map[string]interface{}{
						"bits":     2048,
						"strength": "MEDIUM",
						"type":     "RSA",
					},
					"status": "ACTIVE",
					"subject": map[string]interface{}{
						"common_name":       "ca-name-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})

				stringCACertificate := obj.Object().Value("certificate").String().Raw()
				decodedCertBytes, err := base64.StdEncoding.DecodeString(stringCACertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				decodedCert := strings.Trim(string(decodedCertBytes), "\n")
				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				if certificate.Subject.CommonName != "ca-name-1" {
					t.Errorf("Expected common name to be ca-name-1, got %s", certificate.Subject.CommonName)
				}

				serialNumber := obj.Object().Value("serial_number").String().Raw()
				if serialNumber != utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2) {
					t.Errorf("Expected serial number to be %s, got %s", utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2), serialNumber)
				}
			},
		},
		{
			name: "DuplicateCA",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"subject":{"common_name": "ca-name-1"},"key_metadata":{"type": "RSA", "bits": 4096},"ca_expiration": "9000", "issuance_expiration": "1000", "expiration_type":"DURATION" }`
				r := e.POST("/v1/pki").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusConflict)
				fmt.Println(r.Body().Raw())

			},
		},
		{
			name:                  "InvalidJSON",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"subject":{}`
				_ = e.POST("/v1/pki").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name:                  "ValidationCA:MissingCommonName",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"subject":{"country": "ES"},"key_metadata":{"type": "RSA", "bits": 4096},"ca_expiration": "9000", "issuance_expiration": "1000", "expiration_type":"DURATION" }`
				_ = e.POST("/v1/pki").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name:                  "ValidationCA:BadKeyType",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"subject":{"common_name": "ca-name-1"},"key_metadata":{"type": "---", "bits": 4096},"ca_expiration": "9000", "issuance_expiration": "1000", "expiration_type":"DURATION" }`
				_ = e.POST("/v1/pki").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK)
			},
		},
		{
			name:                  "ValidationCA:BadKeySizeForRSAKey",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"subject":{"common_name": "ca-name-1"},"key_metadata":{"type": "RSA", "bits": 5000},"ca_expiration": "9000", "issuance_expiration": "1000", "expiration_type":"DURATION" }`
				_ = e.POST("/v1/pki").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name:                  "ValidationCA:MissingCADuration",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"subject":{"common_name": "ca-name-1"},"key_metadata":{"type": "RSA", "bits": 4096},"issuance_expiration": "1000", "expiration_type":"DURATION" }`
				_ = e.POST("/v1/pki").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name:                  "ValidationCA:MissingIssuanceDuration",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"subject":{"common_name": "ca-name-1"},"key_metadata":{"type": "RSA", "bits": 4096},"ca_expiration": "1000" }`
				_ = e.POST("/v1/pki").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name:                  "ValidationCA:CADurationIsLessThanIssuanceDuration",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"subject":{"common_name": "ca-name-1"},"key_metadata":{"type": "RSA", "bits": 4096},"ca_expiration": "1000", "issuance_expiration": "9000", "expiration_type":"DURATION" }`
				_ = e.POST("/v1/pki").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			server, svc, err := testUtils.BuildCATestServer()
			//cli, err := testUtils.NewVaultSecretsMock(t)
			//if err != nil {
			//	t.Errorf("%s", err)
			//}
			//server, svc, err := testUtils.BuildCATestServerWithVault(cli)

			if err != nil {
				t.Errorf("%s", err)
			}

			defer server.Close()
			server.Start()

			tc.serviceInitialization(svc)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}

func TestGetCAByName(t *testing.T) {
	tt := []struct {
		name                  string
		serviceInitialization func(svc *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name:                  "EmptyCA",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/v1/pki/ca-name-1").
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "ActiveCA",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {

				obj := e.GET("/v1/pki/ca-name-1").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsMap(map[string]interface{}{
					"key_metadata": map[string]interface{}{
						"bits":     4096,
						"strength": "HIGH",
						"type":     "RSA",
					},
					"status": "ACTIVE",
					"subject": map[string]interface{}{
						"common_name":       "ca-name-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})

				stringCACertificate := obj.Object().Value("certificate").String().Raw()
				decodedCertBytes, err := base64.StdEncoding.DecodeString(stringCACertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				decodedCert := strings.Trim(string(decodedCertBytes), "\n")
				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				if certificate.Subject.CommonName != "ca-name-1" {
					t.Errorf("Expected common name to be ca-name-1, got %s", certificate.Subject.CommonName)
				}

				serialNumber := obj.Object().Value("serial_number").String().Raw()
				if serialNumber != utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2) {
					t.Errorf("Expected serial number to be %s, got %s", utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2), serialNumber)
				}
			},
		},
		{
			name: "RevokedCA",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}

				_, err = (*svc).RevokeCA(context.Background(), &api.RevokeCAInput{
					CAType:           api.CATypePKI,
					CAName:           "ca-name-1",
					RevocationReason: "testing reason",
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {

				obj := e.GET("/v1/pki/ca-name-1").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsMap(map[string]interface{}{
					"key_metadata": map[string]interface{}{
						"bits":     4096,
						"strength": "HIGH",
						"type":     "RSA",
					},
					"status": "REVOKED",
					"subject": map[string]interface{}{
						"common_name":       "ca-name-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})

				stringCACertificate := obj.Object().Value("certificate").String().Raw()
				decodedCertBytes, err := base64.StdEncoding.DecodeString(stringCACertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				decodedCert := strings.Trim(string(decodedCertBytes), "\n")
				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				if certificate.Subject.CommonName != "ca-name-1" {
					t.Errorf("Expected common name to be ca-name-1, got %s", certificate.Subject.CommonName)
				}

				serialNumber := obj.Object().Value("serial_number").String().Raw()
				if serialNumber != utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2) {
					t.Errorf("Expected serial number to be %s, got %s", utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2), serialNumber)
				}
			},
		},
		{
			name: "ExpiredCA",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Second * 5),
					IssuanceExpiration: time.Now().Add(time.Second * 3),
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				CADuration := time.Duration(time.Second * 5)

				time.Sleep(CADuration)

				obj := e.GET("/v1/pki/ca-name-1").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsMap(map[string]interface{}{
					"key_metadata": map[string]interface{}{
						"bits":     4096,
						"strength": "HIGH",
						"type":     "RSA",
					},
					"status": "EXPIRED",
					"subject": map[string]interface{}{
						"common_name":       "ca-name-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})

				stringCACertificate := obj.Object().Value("certificate").String().Raw()
				decodedCertBytes, err := base64.StdEncoding.DecodeString(stringCACertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				decodedCert := strings.Trim(string(decodedCertBytes), "\n")
				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				if certificate.Subject.CommonName != "ca-name-1" {
					t.Errorf("Expected common name to be ca-name-1, got %s", certificate.Subject.CommonName)
				}

				serialNumber := obj.Object().Value("serial_number").String().Raw()
				if serialNumber != utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2) {
					t.Errorf("Expected serial number to be %s, got %s", utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2), serialNumber)
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			server, svc, err := testUtils.BuildCATestServer()
			//cli, err := testUtils.NewVaultSecretsMock(t)
			//if err != nil {
			//	t.Errorf("%s", err)
			//}
			//server, svc, err := testUtils.BuildCATestServerWithVault(cli)
			if err != nil {
				t.Errorf("%s", err)
			}

			defer server.Close()
			server.Start()

			tc.serviceInitialization(svc)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}

func TestGetCAs(t *testing.T) {
	tt := []struct {
		name                  string
		serviceInitialization func(svc *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name:                  "PKI:EmptyList",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/pki").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_cas").ValueEqual("total_cas", 0)
				obj.Object().ContainsKey("cas")

				obj.Object().Value("cas").Array().Empty()
			},
		},
		{
			name: "PKI:OneCA",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/pki").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_cas").ValueEqual("total_cas", 1)
				obj.Object().ContainsKey("cas")

				caObj := obj.Object().Value("cas").Array().First()
				caObj.Object().ContainsMap(map[string]interface{}{
					"key_metadata": map[string]interface{}{
						"bits":     4096,
						"strength": "HIGH",
						"type":     "RSA",
					},
					"status": "ACTIVE",
					"subject": map[string]interface{}{
						"common_name":       "ca-name-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})

				stringCACertificate := caObj.Object().Value("certificate").String().Raw()
				decodedCertBytes, err := base64.StdEncoding.DecodeString(stringCACertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				decodedCert := strings.Trim(string(decodedCertBytes), "\n")
				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				if certificate.Subject.CommonName != "ca-name-1" {
					t.Errorf("Expected common name to be ca-name-1, got %s", certificate.Subject.CommonName)
				}

				serialNumber := caObj.Object().Value("serial_number").String().Raw()
				if serialNumber != utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2) {
					t.Errorf("Expected serial number to be %s, got %s", utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2), serialNumber)
				}
			},
		},
		{
			name: "PKI:OneExpiredCA",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Second * 6),
					IssuanceExpiration: time.Now().Add(time.Second * 2),
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				time.Sleep(time.Second * 6)

				obj := e.GET("/v1/pki").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_cas").ValueEqual("total_cas", 1)
				obj.Object().ContainsKey("cas")

				caObj := obj.Object().Value("cas").Array().First()
				caObj.Object().ContainsMap(map[string]interface{}{
					"key_metadata": map[string]interface{}{
						"bits":     4096,
						"strength": "HIGH",
						"type":     "RSA",
					},
					"status": "EXPIRED",
					"subject": map[string]interface{}{
						"common_name":       "ca-name-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})
				stringCACertificate := caObj.Object().Value("certificate").String().Raw()
				decodedCertBytes, err := base64.StdEncoding.DecodeString(stringCACertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				decodedCert := strings.Trim(string(decodedCertBytes), "\n")
				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				if certificate.Subject.CommonName != "ca-name-1" {
					t.Errorf("Expected common name to be ca-name-1, got %s", certificate.Subject.CommonName)
				}

				serialNumber := caObj.Object().Value("serial_number").String().Raw()
				if serialNumber != utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2) {
					t.Errorf("Expected serial number to be %s, got %s", utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2), serialNumber)
				}
			},
		},
		{
			name: "PKI:10CAsWithBasicQueryParameters",
			serviceInitialization: func(svc *service.Service) {
				for i := 0; i < 10; i++ {
					_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
						CAType: api.CATypePKI,
						Subject: api.Subject{
							CommonName: "ca-name-" + strconv.Itoa(i),
						},
						KeyMetadata: api.KeyMetadata{
							KeyType: api.RSA,
							KeyBits: 4096,
						},
						ExpirationType:     api.ExpirationTypeDuration,
						CAExpiration:       time.Now().Add(time.Hour * 5),
						IssuanceExpiration: time.Now().Add(time.Hour),
					})

					if err != nil {
						t.Fatalf("%s", err)
					}
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/pki").WithQuery("limit", 3).WithQuery("offset", 0).WithQuery("sort_by", "ca_name.asc").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_cas").ValueEqual("total_cas", 10)
				obj.Object().ContainsKey("cas").Value("cas").Array().Length().Equal(3)

				casIter := obj.Object().ContainsKey("cas").Value("cas").Array().Iter()
				for idx, v := range casIter {
					caName := v.Object().Value("name").String().Raw()
					if caName != "ca-name-"+strconv.Itoa(idx) {
						t.Errorf("Expected CA name to be ca-name-%d, got %s", idx, caName)
					}
				}

				obj = e.GET("/v1/pki").WithQuery("limit", 3).WithQuery("offset", 3).WithQuery("sort_by", "ca_name.asc").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_cas").ValueEqual("total_cas", 10)
				obj.Object().ContainsKey("cas").Value("cas").Array().Length().Equal(3)
				casIter = obj.Object().ContainsKey("cas").Value("cas").Array().Iter()
				for idx, v := range casIter {
					caName := v.Object().Value("name").String().Raw()
					if caName != "ca-name-"+strconv.Itoa(idx+3) {
						t.Errorf("Expected CA name to be ca-name-%d, got %s", idx+3, caName)
					}
				}
			},
		},
		{
			name: "PKI:DatesFilters",
			serviceInitialization: func(svc *service.Service) {
				caSets := []string{"set1", "set2"}
				for _, caSet := range caSets {
					for i := 0; i < 5; i++ {
						_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
							CAType: api.CATypePKI,
							Subject: api.Subject{
								CommonName: caSet + "-ca-name-" + strconv.Itoa(i),
							},
							KeyMetadata: api.KeyMetadata{
								KeyType: api.RSA,
								KeyBits: 4096,
							},
							ExpirationType:     api.ExpirationTypeDuration,
							CAExpiration:       time.Now().Add(time.Hour * 5),
							IssuanceExpiration: time.Now().Add(time.Hour),
						})

						if err != nil {
							t.Fatalf("%s", err)
						}
					}
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/pki").WithQuery("limit", 3).WithQuery("offset", 0).WithQuery("sort_by", "ca_name.asc").WithQuery("filter", "ca_name[contains]=set1-ca-name").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_cas").ValueEqual("total_cas", 5)
				obj.Object().ContainsKey("cas").Value("cas").Array().Length().Equal(3)

				casIter := obj.Object().ContainsKey("cas").Value("cas").Array().Iter()
				for idx, v := range casIter {
					caName := v.Object().Value("name").String().Raw()
					if caName != "set1-ca-name-"+strconv.Itoa(idx) {
						t.Errorf("Expected CA name to be set1-ca-name-%d, got %s", idx, caName)
					}
				}

				obj = e.GET("/v1/pki").WithQuery("limit", 3).WithQuery("offset", 3).WithQuery("sort_by", "ca_name.asc").WithQuery("filter", "ca_name[contains]=set1-ca-name").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_cas").ValueEqual("total_cas", 5)
				obj.Object().ContainsKey("cas").Value("cas").Array().Length().Equal(2)
				casIter = obj.Object().ContainsKey("cas").Value("cas").Array().Iter()
				for idx, v := range casIter {
					caName := v.Object().Value("name").String().Raw()
					if caName != "set1-ca-name-"+strconv.Itoa(idx+3) {
						t.Errorf("Expected CA name to be set1-ca-name-%d, got %s", idx+3, caName)
					}
				}
			},
		},
		{
			name: "PKI:StringFilters:Contains",
			serviceInitialization: func(svc *service.Service) {
				caSets := []string{"set1", "set2"}
				for _, caSet := range caSets {
					for i := 0; i < 5; i++ {
						_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
							CAType: api.CATypePKI,
							Subject: api.Subject{
								CommonName: caSet + "-ca-name-" + strconv.Itoa(i),
							},
							KeyMetadata: api.KeyMetadata{
								KeyType: api.RSA,
								KeyBits: 4096,
							},
							ExpirationType:     api.ExpirationTypeDuration,
							CAExpiration:       time.Now().Add(time.Hour * 5),
							IssuanceExpiration: time.Now().Add(time.Hour),
						})

						if err != nil {
							t.Fatalf("%s", err)
						}
					}
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/pki").WithQuery("limit", 3).WithQuery("offset", 0).WithQuery("sort_by", "ca_name.asc").WithQuery("filter", "ca_name[contains]=set1-ca-name").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_cas").ValueEqual("total_cas", 5)
				obj.Object().ContainsKey("cas").Value("cas").Array().Length().Equal(3)

				casIter := obj.Object().ContainsKey("cas").Value("cas").Array().Iter()
				for idx, v := range casIter {
					caName := v.Object().Value("name").String().Raw()
					if caName != "set1-ca-name-"+strconv.Itoa(idx) {
						t.Errorf("Expected CA name to be set1-ca-name-%d, got %s", idx, caName)
					}
				}

				obj = e.GET("/v1/pki").WithQuery("limit", 3).WithQuery("offset", 3).WithQuery("sort_by", "ca_name.asc").WithQuery("filter", "ca_name[contains]=set1-ca-name").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_cas").ValueEqual("total_cas", 5)
				obj.Object().ContainsKey("cas").Value("cas").Array().Length().Equal(2)
				casIter = obj.Object().ContainsKey("cas").Value("cas").Array().Iter()
				for idx, v := range casIter {
					caName := v.Object().Value("name").String().Raw()
					if caName != "set1-ca-name-"+strconv.Itoa(idx+3) {
						t.Errorf("Expected CA name to be set1-ca-name-%d, got %s", idx+3, caName)
					}
				}
			},
		},
		{
			name: "PKI:MultipleFilters",
			serviceInitialization: func(svc *service.Service) {
				caSets := []string{"set1", "set2"}
				for _, caSet := range caSets {
					for i := 0; i < 4; i++ {
						_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
							CAType: api.CATypePKI,
							Subject: api.Subject{
								CommonName: caSet + "-ca-name-" + strconv.Itoa(i),
							},
							KeyMetadata: api.KeyMetadata{
								KeyType: api.RSA,
								KeyBits: 4096,
							},
							ExpirationType:     api.ExpirationTypeDuration,
							CAExpiration:       time.Now().Add(time.Hour * 5),
							IssuanceExpiration: time.Now().Add(time.Hour),
						})

						if err != nil {
							t.Fatalf("%s", err)
						}

						if i%2 == 1 {
							_, err = (*svc).RevokeCA(context.Background(), &api.RevokeCAInput{
								CAType:           api.CATypePKI,
								CAName:           caSet + "-ca-name-" + strconv.Itoa(i),
								RevocationReason: "testing",
							})
							if err != nil {
								t.Fatalf("%s", err)
							}
						}
					}
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/pki").WithQuery("limit", 3).WithQuery("offset", 0).WithQuery("sort_by", "ca_name.asc").
					WithQuery("filter", "ca_name[contains]=set2-ca-name").
					WithQuery("filter", "status[equals]=ACTIVE").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_cas").ValueEqual("total_cas", 2)
				obj.Object().ContainsKey("cas").Value("cas").Array().Length().Equal(2)

				casIter := obj.Object().ContainsKey("cas").Value("cas").Array().Iter()
				for idx, v := range casIter {
					caName := v.Object().Value("name").String().Raw()
					if caName != "set2-ca-name-"+strconv.Itoa(idx*2) {
						t.Errorf("Expected CA name to be set2-ca-name-%d, got %s", idx*2, caName)
					}
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			server, svc, err := testUtils.BuildCATestServer()
			//cli, err := testUtils.NewVaultSecretsMock(t)
			//if err != nil {
			//	t.Errorf("%s", err)
			//}
			//server, svc, err := testUtils.BuildCATestServerWithVault(cli)

			if err != nil {
				t.Errorf("%s", err)
			}

			defer server.Close()
			server.Start()

			tc.serviceInitialization(svc)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}

func TestRevokeCA(t *testing.T) {
	tt := []struct {
		name                  string
		serviceInitialization func(svc *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name:                  "EmptyCA",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"revocation_reason":"testing revocation"}`
				_ = e.DELETE("/v1/pki/ca-name-1").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "ShouldRevokeCA",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 2048,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {

				reqBody := `{"revocation_reason":"testing revocation"}`
				obj := e.DELETE("/v1/pki/ca-name-1").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("revocation_timestamp")
				obj.Object().ContainsMap(map[string]interface{}{
					"key_metadata": map[string]interface{}{
						"bits":     2048,
						"strength": "MEDIUM",
						"type":     "RSA",
					},
					"status":            "REVOKED",
					"revocation_reason": "testing revocation",
					"subject": map[string]interface{}{
						"common_name":       "ca-name-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})

			},
		},
		{
			name: "ShouldRevokeCAAndIssuedCertificates",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 2048,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}

				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				template := x509.CertificateRequest{
					Subject: pkix.Name{
						CommonName: "device-1",
					},
				}
				csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
				if err != nil {
					t.Errorf("%s", err)
				}

				csr, err := x509.ParseCertificateRequest(csrBytes)
				if err != nil {
					t.Errorf("%s", err)
				}

				_, err = (*svc).SignCertificateRequest(context.Background(), &api.SignCertificateRequestInput{
					CAType:                    api.CATypePKI,
					CAName:                    "ca-name-1",
					SignVerbatim:              true,
					CertificateSigningRequest: csr,
					CommonName:                csr.Subject.CommonName,
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				issuanceDuration := time.Duration(time.Hour * 1)

				reqBody := `{"revocation_reason":"testing revocation"}`
				obj := e.DELETE("/v1/pki/ca-name-1").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("revocation_timestamp")
				obj.Object().ContainsMap(map[string]interface{}{
					"issuance_duration": int(issuanceDuration.Seconds()),
					"key_metadata": map[string]interface{}{
						"bits":     2048,
						"strength": "MEDIUM",
						"type":     "RSA",
					},
					"status":            "REVOKED",
					"revocation_reason": "testing revocation",
					"subject": map[string]interface{}{
						"common_name":       "ca-name-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})

				obj = e.GET("/v1/pki/ca-name-1/certificates").WithQuery("limit", 3).WithQuery("offset", 0).
					Expect().
					Status(http.StatusOK).JSON()

				certIter := obj.Object().ContainsKey("certificates").Value("certificates").Array().Iter()
				for idx, v := range certIter {
					status := v.Object().Value("status").String().Raw()
					if status != "REVOKED" {
						t.Errorf("Expected certificate %d to be REVOKED, but it was %s", idx, status)
					}
				}

			},
		},
		{
			name: "Validation:ContainsRevocationReason",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 2048,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{}`
				_ = e.DELETE("/v1/pki/ca-name-1").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "Validation:ContainsRevocationReasonNonEmpty",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 2048,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"revocation_reason":""}`
				_ = e.DELETE("/v1/pki/ca-name-1").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			server, svc, err := testUtils.BuildCATestServer()
			//cli, err := testUtils.NewVaultSecretsMock(t)
			//if err != nil {
			//	t.Errorf("%s", err)
			//}
			//server, svc, err := testUtils.BuildCATestServerWithVault(cli)

			if err != nil {
				t.Errorf("%s", err)
			}

			defer server.Close()
			server.Start()

			tc.serviceInitialization(svc)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}

func TestSignCertificateRequest(t *testing.T) {
	tt := []struct {
		name                  string
		serviceInitialization func(svc *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name:                  "EmptyCA",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, csr := generateBase64EncodedCertificateRequest("device-1")
				reqBody := `{
					"certificate_request":"` + csr + `",
					"sign_verbatim":true
				}`
				_ = e.POST("/v1/pki/ca-name-1/sign").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "ShouldSignVerbatim",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				//issuanceDuration := time.Hour
				_, csr := generateBase64EncodedCertificateRequest("device-1")
				reqBody := `{
					"certificate_request":"` + csr + `",
					"sign_verbatim":true
				}`
				obj := e.POST("/v1/pki/ca-name-1/sign").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("ca_certificate")
				obj.Object().ContainsKey("certificate")

				stringCertificate := obj.Object().Value("certificate").String().Raw()
				decodedCertBytes, err := base64.StdEncoding.DecodeString(stringCertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				decodedCert := strings.Trim(string(decodedCertBytes), "\n")
				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				if certificate.Subject.CommonName != "device-1" {
					t.Errorf("Expected common name to be device-1, got %s", certificate.Subject.CommonName)
				}

				if certificate.Issuer.CommonName != "ca-name-1" {
					t.Errorf("Expected Issuer common name to be ca-name-1, got %s", certificate.Issuer.CommonName)
				}

				/*if certificate.NotAfter.Sub(certificate.NotBefore) != issuanceDuration {
					t.Errorf("Expected certificate duration to be %s, got %s", issuanceDuration, certificate.NotAfter.Sub(certificate.NotBefore))
				}*/
			},
		},
		{
			name: "ShouldSignWithProvidedCommonName",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				//issuanceDuration := time.Hour

				_, csr := generateBase64EncodedCertificateRequest("device-1")
				reqBody := `{
					"certificate_request":"` + csr + `",
					"sign_verbatim":false,
					"common_name":"device-2"
				}`
				obj := e.POST("/v1/pki/ca-name-1/sign").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("ca_certificate")
				obj.Object().ContainsKey("certificate")

				stringCertificate := obj.Object().Value("certificate").String().Raw()
				decodedCertBytes, err := base64.StdEncoding.DecodeString(stringCertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				decodedCert := strings.Trim(string(decodedCertBytes), "\n")
				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				if certificate.Subject.CommonName != "device-2" {
					t.Errorf("Expected common name to be device-2, got %s", certificate.Subject.CommonName)
				}

				if certificate.Issuer.CommonName != "ca-name-1" {
					t.Errorf("Expected Issuer common name to be ca-name-1, got %s", certificate.Issuer.CommonName)
				}

				/*if certificate.NotAfter.Sub(certificate.NotBefore) != issuanceDuration {
					t.Errorf("Expected certificate duration to be %s, got %s", issuanceDuration, certificate.NotAfter.Sub(certificate.NotBefore))
				}*/
			},
		},
		{
			name:                  "Validation:NotBase64Encoded",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, csr := generateBase64EncodedCertificateRequest("device-1")
				decodedCsr, err := base64.StdEncoding.DecodeString(csr)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				reqBody := `{
					"certificate_request":"` + string(decodedCsr) + `",
					"sign_verbatim":true
				}`

				_ = e.POST("/v1/pki/ca-name-1/sign").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name:                  "Validation:NotPEMEncoded",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				csr := base64.StdEncoding.EncodeToString([]byte("thisIsNoPEM"))
				reqBody := `{
					"certificate_request":"` + csr + `",
					"sign_verbatim":true
				}`

				_ = e.POST("/v1/pki/ca-name-1/sign").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name:                  "Validation:SignVerbatimFalseWithNoCommonName",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, csr := generateBase64EncodedCertificateRequest("device-1")
				reqBody := `{
					"certificate_request":"` + csr + `",
					"sign_verbatim":false
				}`

				_ = e.POST("/v1/pki/ca-name-1/sign").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			server, svc, err := testUtils.BuildCATestServer()
			//cli, err := testUtils.NewVaultSecretsMock(t)
			//if err != nil {
			//	t.Errorf("%s", err)
			//}
			//server, svc, err := testUtils.BuildCATestServerWithVault(cli)

			if err != nil {
				t.Errorf("%s", err)
			}

			defer server.Close()
			server.Start()

			tc.serviceInitialization(svc)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}

func TestRevokeCertificate(t *testing.T) {
	tt := []struct {
		name                  string
		serviceInitialization func(svc *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name:                  "EmptyCA",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"revocation_reason":"testing revocation"}`
				_ = e.DELETE("/v1/pki/ca-name-1/certificates/123456789").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "EmptyCertificate",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"revocation_reason":"testing revocation"}`
				_ = e.DELETE("/v1/pki/ca-name-1/certificates/123456789").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "ShouldRevokeCertificate",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, csr := generateBase64EncodedCertificateRequest("device-1")
				reqBody := `{
					"certificate_request":"` + csr + `",
					"sign_verbatim":true
				}`
				obj := e.POST("/v1/pki/ca-name-1/sign").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("ca_certificate")
				obj.Object().ContainsKey("certificate")

				stringCertificate := obj.Object().Value("certificate").String().Raw()
				decodedCert, err := base64.StdEncoding.DecodeString(stringCertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				serialNumber := utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2)

				reqBody = `{"revocation_reason":"testing revocation"}`
				obj = e.DELETE("/v1/pki/ca-name-1/certificates/" + serialNumber).WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("revocation_timestamp")
				obj.Object().ContainsMap(map[string]interface{}{
					"key_metadata": map[string]interface{}{
						"bits":     2048,
						"strength": "MEDIUM",
						"type":     "RSA",
					},
					"status":            "REVOKED",
					"revocation_reason": "testing revocation",
					"subject": map[string]interface{}{
						"common_name":       "device-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})

			},
		},
		{
			name:                  "Validation:ContainsRevocationReason",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{}`
				_ = e.DELETE("/v1/pki/ca-name-1/certificates/1234567879").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name:                  "Validation:ContainsRevocationReasonNonEmpty",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				reqBody := `{"revocation_reason":""}`
				_ = e.DELETE("/v1/pki/ca-name-1/certificates/1234567879").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			server, svc, err := testUtils.BuildCATestServer()
			//cli, err := testUtils.NewVaultSecretsMock(t)
			//if err != nil {
			//	t.Errorf("%s", err)
			//}
			//server, svc, err := testUtils.BuildCATestServerWithVault(cli)

			if err != nil {
				t.Errorf("%s", err)
			}

			defer server.Close()
			server.Start()

			tc.serviceInitialization(svc)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}

func TestGetCertificateBySerialNumber(t *testing.T) {
	tt := []struct {
		name                  string
		serviceInitialization func(svc *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name:                  "NoCA",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/v1/pki/ca-name-1/certificates").
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "EmptyCA",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/v1/pki/ca-name-1/certificates/1234588").
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "ShouldGetCertificate",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_, csr := generateBase64EncodedCertificateRequest("device-1")
				reqBody := `{
					"certificate_request":"` + csr + `",
					"sign_verbatim":true
				}`
				obj := e.POST("/v1/pki/ca-name-1/sign").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("ca_certificate")
				obj.Object().ContainsKey("certificate")

				stringCertificate := obj.Object().Value("certificate").String().Raw()
				decodedCert, err := base64.StdEncoding.DecodeString(stringCertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				serialNumber := utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2)

				obj = e.GET("/v1/pki/ca-name-1/certificates/" + serialNumber).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsMap(map[string]interface{}{
					"key_metadata": map[string]interface{}{
						"bits":     2048,
						"strength": "MEDIUM",
						"type":     "RSA",
					},
					"status":        "ACTIVE",
					"serial_number": serialNumber,
					"subject": map[string]interface{}{
						"common_name":       "device-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})
			},
		},
		{
			name: "ShouldGetRevokedCertificate",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Second * 3),
				})
				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				issuanceDuration := time.Second * 3
				_, csr := generateBase64EncodedCertificateRequest("device-1")
				reqBody := `{
					"certificate_request":"` + csr + `",
					"sign_verbatim":true
				}`
				obj := e.POST("/v1/pki/ca-name-1/sign").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("ca_certificate")
				obj.Object().ContainsKey("certificate")

				stringCertificate := obj.Object().Value("certificate").String().Raw()
				decodedCert, err := base64.StdEncoding.DecodeString(stringCertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				serialNumber := utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2)

				time.Sleep(issuanceDuration)

				obj = e.GET("/v1/pki/ca-name-1/certificates/" + serialNumber).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsMap(map[string]interface{}{
					"key_metadata": map[string]interface{}{
						"bits":     2048,
						"strength": "MEDIUM",
						"type":     "RSA",
					},
					"status":        "EXPIRED",
					"serial_number": serialNumber,
					"subject": map[string]interface{}{
						"common_name":       "device-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			server, svc, err := testUtils.BuildCATestServer()
			//cli, err := testUtils.NewVaultSecretsMock(t)
			//if err != nil {
			//	t.Errorf("%s", err)
			//}
			//server, svc, err := testUtils.BuildCATestServerWithVault(cli)

			if err != nil {
				t.Errorf("%s", err)
			}

			defer server.Close()
			server.Start()

			tc.serviceInitialization(svc)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}

func TestGetCertificates(t *testing.T) {
	tt := []struct {
		name                  string
		serviceInitialization func(svc *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name:                  "PKI:NoCA",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/v1/pki/ca-name-1/certificates").
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "PKI:EmptyList",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {

				obj := e.GET("/v1/pki/ca-name-1/certificates").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_certificates").ValueEqual("total_certificates", 0)
				obj.Object().ContainsKey("certificates")

				obj.Object().Value("certificates").Array().Empty()
			},
		},
		{
			name: "PKI:OneCertificate",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})

				if err != nil {
					t.Errorf("%s", err)
				}

				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				template := x509.CertificateRequest{
					Subject: pkix.Name{
						CommonName: "device-1",
					},
				}
				csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
				if err != nil {
					t.Errorf("%s", err)
				}

				csr, err := x509.ParseCertificateRequest(csrBytes)
				if err != nil {
					t.Errorf("%s", err)
				}

				_, err = (*svc).SignCertificateRequest(context.Background(), &api.SignCertificateRequestInput{
					CAType:                    api.CATypePKI,
					CAName:                    "ca-name-1",
					SignVerbatim:              true,
					CertificateSigningRequest: csr,
				})

				if err != nil {
					t.Errorf("%s", err)
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				//issuanceDuration := time.Duration(time.Hour)

				obj := e.GET("/v1/pki/ca-name-1/certificates").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_certificates").ValueEqual("total_certificates", 1)
				obj.Object().ContainsKey("certificates")

				certObj := obj.Object().Value("certificates").Array().First()
				certObj.Object().ContainsMap(map[string]interface{}{
					"key_metadata": map[string]interface{}{
						"bits":     2048,
						"strength": "MEDIUM",
						"type":     "RSA",
					},
					"status": "ACTIVE",
					"subject": map[string]interface{}{
						"common_name":       "device-1",
						"country":           "",
						"locality":          "",
						"organization":      "",
						"organization_unit": "",
						"state":             "",
					},
				})

				/*intValidTo := certObj.Object().Value("valid_to").Number().Raw()
				intValidFrom := certObj.Object().Value("valid_from").Number().Raw()

				validTo := time.UnixMilli(int64(intValidTo))
				validFrom := time.UnixMilli(int64(intValidFrom))

				if validTo.Sub(validFrom).Seconds() != issuanceDuration.Seconds() {
					t.Errorf("Expected Certificate duration to be %f seconds, got %f", issuanceDuration.Seconds(), validTo.Sub(validFrom).Seconds())
				}*/

				stringCACertificate := certObj.Object().Value("certificate").String().Raw()
				decodedCertBytes, err := base64.StdEncoding.DecodeString(stringCACertificate)
				if err != nil {
					t.Errorf("Error decoding certificate: %s", err)
				}

				decodedCert := strings.Trim(string(decodedCertBytes), "\n")
				block, _ := pem.Decode([]byte(decodedCert))
				if block == nil {
					t.Errorf("failed to decode PEM block containing the certificate")
					return
				}

				certificate, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("failed to parse certificate: %s", err)
					return
				}

				if certificate.Subject.CommonName != "device-1" {
					t.Errorf("Expected common name to device-1, got %s", certificate.Subject.CommonName)
				}

				serialNumber := certObj.Object().Value("serial_number").String().Raw()
				if serialNumber != utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2) {
					t.Errorf("Expected serial number to be %s, got %s", utils.InsertNth(utils.ToHexInt(certificate.SerialNumber), 2), serialNumber)
				}
			},
		},
		{
			name: "10CertificatesWithBasicQueryParameters",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Errorf("%s", err)
				}
				for i := 0; i < 10; i++ {
					key, _ := rsa.GenerateKey(rand.Reader, 2048)
					template := x509.CertificateRequest{
						Subject: pkix.Name{
							CommonName: "device-" + strconv.Itoa(i),
						},
					}
					csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
					if err != nil {
						t.Errorf("%s", err)
					}

					csr, err := x509.ParseCertificateRequest(csrBytes)
					if err != nil {
						t.Errorf("%s", err)
					}

					_, err = (*svc).SignCertificateRequest(context.Background(), &api.SignCertificateRequestInput{
						CAType:                    api.CATypePKI,
						CAName:                    "ca-name-1",
						SignVerbatim:              true,
						CertificateSigningRequest: csr,
					})

					if err != nil {
						t.Errorf("%s", err)
					}
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/pki/ca-name-1/certificates").WithQuery("limit", 3).WithQuery("offset", 0).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_certificates").ValueEqual("total_certificates", 10)
				obj.Object().ContainsKey("certificates").Value("certificates").Array().Length().Equal(3)

				casIter := obj.Object().ContainsKey("certificates").Value("certificates").Array().Iter()
				for idx, v := range casIter {
					commonName := v.Object().Value("subject").Object().Value("common_name").String().Raw()
					if commonName != "device-"+strconv.Itoa(idx) {
						t.Errorf("Expected Common Name name to be device-%d, got %s", idx, commonName)
					}
				}
			},
		},
		{
			name: "10ExpiredCertificatesWithBasicQueryParameters",
			serviceInitialization: func(svc *service.Service) {
				_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 4096,
					},
					ExpirationType:     api.ExpirationTypeDuration,
					CAExpiration:       time.Now().Add(time.Hour * 5),
					IssuanceExpiration: time.Now().Add(time.Hour * 3),
				})
				if err != nil {
					t.Errorf("%s", err)
				}
				for i := 0; i < 10; i++ {
					key, _ := rsa.GenerateKey(rand.Reader, 2048)
					template := x509.CertificateRequest{
						Subject: pkix.Name{
							CommonName: "device-" + strconv.Itoa(i),
						},
					}
					csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
					if err != nil {
						t.Errorf("%s", err)
					}

					csr, err := x509.ParseCertificateRequest(csrBytes)
					if err != nil {
						t.Errorf("%s", err)
					}

					_, err = (*svc).SignCertificateRequest(context.Background(), &api.SignCertificateRequestInput{
						CAType:                    api.CATypePKI,
						CAName:                    "ca-name-1",
						SignVerbatim:              true,
						CertificateSigningRequest: csr,
					})

					if err != nil {
						t.Errorf("%s", err)
					}
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				time.Sleep(time.Second * 3)

				obj := e.GET("/v1/pki/ca-name-1/certificates").WithQuery("limit", 3).WithQuery("offset", 0).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_certificates").ValueEqual("total_certificates", 10)
				obj.Object().ContainsKey("certificates").Value("certificates").Array().Length().Equal(3)

				casIter := obj.Object().ContainsKey("certificates").Value("certificates").Array().Iter()
				for idx, v := range casIter {
					commonName := v.Object().Value("subject").Object().Value("common_name").String().Raw()
					if commonName != "device-"+strconv.Itoa(idx) {
						t.Errorf("Expected Common Name name to be device-%d, got %s", idx, commonName)
					}
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			server, svc, err := testUtils.BuildCATestServer()
			//cli, err := testUtils.NewVaultSecretsMock(t)
			//if err != nil {
			//	t.Errorf("%s", err)
			//}
			//server, svc, err := testUtils.BuildCATestServerWithVault(cli)

			if err != nil {
				t.Errorf("%s", err)
			}

			defer server.Close()
			server.Start()

			tc.serviceInitialization(svc)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}

func TestStats(t *testing.T) {
	tt := []struct {
		name                  string
		serviceInitialization func(svc *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name:                  "EmptyCAs",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/stats").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("cas").ValueEqual("cas", 0)
				obj.Object().ContainsKey("issued_certificates").ValueEqual("issued_certificates", 0)
				obj.Object().ContainsKey("scan_date")
			},
		},
		{
			name: "TwoCAsAndTenCertificates",
			serviceInitialization: func(svc *service.Service) {
				totlaCAs := 2
				totalCertificatesPerCA := 5

				for i := 0; i < totlaCAs; i++ {
					_, err := (*svc).CreateCA(context.Background(), &api.CreateCAInput{
						CAType: api.CATypePKI,
						Subject: api.Subject{
							CommonName: "ca-name-" + strconv.Itoa(i+1),
						},
						KeyMetadata: api.KeyMetadata{
							KeyType: api.RSA,
							KeyBits: 4096,
						},
						ExpirationType:     api.ExpirationTypeDuration,
						CAExpiration:       time.Now().Add(time.Hour * 5),
						IssuanceExpiration: time.Now().Add(time.Hour),
					})
					if err != nil {
						t.Errorf("%s", err)
					}

					for j := 0; j < totalCertificatesPerCA; j++ {
						key, _ := rsa.GenerateKey(rand.Reader, 2048)
						template := x509.CertificateRequest{
							Subject: pkix.Name{
								CommonName: "device-" + strconv.Itoa(j+1),
							},
						}
						csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
						if err != nil {
							t.Errorf("%s", err)
						}

						csr, err := x509.ParseCertificateRequest(csrBytes)
						if err != nil {
							t.Errorf("%s", err)
						}

						_, err = (*svc).SignCertificateRequest(context.Background(), &api.SignCertificateRequestInput{
							CAType:                    api.CATypePKI,
							CAName:                    "ca-name-" + strconv.Itoa(i+1),
							SignVerbatim:              true,
							CertificateSigningRequest: csr,
							CommonName:                csr.Subject.CommonName,
						})

						if err != nil {
							t.Errorf("%s", err)
						}
					}
				}
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/stats").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("cas").ValueEqual("cas", 2)
				obj.Object().ContainsKey("issued_certificates").ValueEqual("issued_certificates", 10)
				obj.Object().ContainsKey("scan_date")
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			server, svc, err := testUtils.BuildCATestServer()
			//cli, err := testUtils.NewVaultSecretsMock(t)
			//if err != nil {
			//	t.Errorf("%s", err)
			//}
			//server, svc, err := testUtils.BuildCATestServerWithVault(cli)

			if err != nil {
				t.Errorf("%s", err)
			}

			defer server.Close()
			server.Start()

			tc.serviceInitialization(svc)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}

func TestHealth(t *testing.T) {
	tt := []struct {
		name                  string
		serviceInitialization func(svc *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name:                  "CorrectHealth",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/health").
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("healthy")
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			server, svc, err := testUtils.BuildCATestServer()
			//cli, err := testUtils.NewVaultSecretsMock(t)
			//if err != nil {
			//	t.Errorf("%s", err)
			//}
			//server, svc, err := testUtils.BuildCATestServerWithVault(cli)

			if err != nil {
				t.Errorf("%s", err)
			}

			defer server.Close()
			server.Start()

			tc.serviceInitialization(svc)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}

func generateBase64EncodedCertificateRequest(commonName string) (*rsa.PrivateKey, string) {
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

	pemEncodedBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	csrBase64 := base64.StdEncoding.EncodeToString(pemEncodedBytes)
	return key, csrBase64
}
