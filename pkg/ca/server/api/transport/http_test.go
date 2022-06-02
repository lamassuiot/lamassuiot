package transport

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/mocks"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/secrets/vault"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/opentracing/opentracing-go"

	"github.com/gavv/httpexpect/v2"
)

func TestCAHandler(t *testing.T) {
	//var ca dto.Cert
	var x509Certificate *x509.Certificate
	tt := []struct {
		name                  string
		serviceInitialization func(s *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name: "GetCAs InvalidPath",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/pki/pki/pki").
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "Health",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/health").
					Expect().
					Status(http.StatusOK).JSON()

			},
		},
		{
			name: "GetIssuedCert InvalidCaName",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/pki/lamassu/issued").
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "SignCertificate InvalidCaName",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				csrString := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0="
				req := fmt.Sprintf(`{"csr":"%s","sign_verbatim":true}`, csrString)
				_ = e.POST("/pki/123/sign").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "Stats EmptyCAs",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/stats").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ValueEqual("cas", 0)

			},
		},
		{
			name: "Stats",
			serviceInitialization: func(s *service.Service) {
				data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0=")
				block, _ := pem.Decode([]byte(data))
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
				cert, _ := (*s).SignCertificate(ctx, dto.Pki, "test", *csr, true, *&csr.Subject.CommonName)
				data, _ = base64.StdEncoding.DecodeString(cert.Crt)
				block, _ = pem.Decode([]byte(data))
				x509Certificate, _ = x509.ParseCertificate(block.Bytes)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/stats").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ValueEqual("cas", 1)
				obj.Object().ValueEqual("issued_certs", 1)

			},
		},
		{
			name: "GetCAs DmsEnroller",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.DmsEnroller, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/dmsenroller").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().Value("total_cas").Equal(1)
				obj.Object().Value("cas").Array().Element(0).Object().ValueEqual("status", "issued")
				obj.Object().Value("cas").Array().Element(0).Object().ContainsKey("name")
				ca_name := obj.Object().Value("cas").Array().Element(0).Object().Value("name").String().Raw()
				obj.Object().Value("cas").Array().Element(0).Object().ContainsKey("serial_number")
				obj.Object().Value("cas").Array().Element(0).Object().ContainsKey("subject")
				obj.Object().Value("cas").Array().Element(0).Object().Value("subject").Object().ValueEqual("common_name", ca_name)
				obj.Object().Value("cas").Array().Element(0).Object().ContainsKey("key_metadata")
				obj.Object().Value("cas").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("cas").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Object().Value("cas").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("type")
			},
		},
		{
			name: "GetCAs",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/pki").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().Value("total_cas").Equal(1)
				obj.Object().Value("cas").Array().Element(0).Object().ValueEqual("status", "issued")
				obj.Object().Value("cas").Array().Element(0).Object().ContainsKey("name")
				ca_name := obj.Object().Value("cas").Array().Element(0).Object().Value("name").String().Raw()
				obj.Object().Value("cas").Array().Element(0).Object().ContainsKey("serial_number")
				obj.Object().Value("cas").Array().Element(0).Object().ContainsKey("subject")
				obj.Object().Value("cas").Array().Element(0).Object().Value("subject").Object().ValueEqual("common_name", ca_name)
				obj.Object().Value("cas").Array().Element(0).Object().ContainsKey("key_metadata")
				obj.Object().Value("cas").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("cas").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Object().Value("cas").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("type")
			},
		},
		{
			name: "CreateCA DuplicateCA",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60 * 24
				enrollerTTL := 60 * 60
				req := fmt.Sprintf(`{"key_metadata":{"type":"RSA","bits":4096},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				_ = e.POST("/pki/test").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusConflict)
			},
		},
		{
			name: "CreateCA RSAKey",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60 * 24
				enrollerTTL := 60 * 60
				req := fmt.Sprintf(`{"key_metadata":{"type":"RSA","bits":2048},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				obj := e.POST("/pki/test").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ValueEqual("status", "issued")
				obj.Object().ContainsKey("name")
				obj.Object().ContainsKey("serial_number")
				obj.Object().ContainsKey("subject")
				obj.Object().Value("subject").Object().ValueEqual("common_name", obj.Object().Value("name").String().Raw())
				obj.Object().ContainsKey("key_metadata")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")

			},
		},
		{
			name: "CreateCA InvalidJSONFormat",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60 * 24
				enrollerTTL := 60 * 60
				req := fmt.Sprintf(`"key_metadata":{"type":"RSA","bits":2048},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				_ = e.POST("/pki/test").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "CreateCA ECDSAKey",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60 * 24
				enrollerTTL := 60 * 60
				req := fmt.Sprintf(`{"key_metadata":{"type":"EC","bits":224},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				obj := e.POST("/pki/test").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ValueEqual("status", "issued")
				obj.Object().ContainsKey("name")
				obj.Object().ContainsKey("serial_number")
				obj.Object().ContainsKey("subject")
				obj.Object().Value("subject").Object().ValueEqual("common_name", obj.Object().Value("name").String().Raw())
				obj.Object().ContainsKey("key_metadata")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")

			},
		},
		{
			name: "CreateCA MissingCaName",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60 * 24
				enrollerTTL := 60 * 60
				req := fmt.Sprintf(`{"key_metadata":{"type":"RSA","bits":2048},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				_ = e.POST("/pki/").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "GetCAs MethodNotAllowed",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60 * 24
				enrollerTTL := 60 * 60
				req := fmt.Sprintf(`{"key_metadata":{"type":"RSA","bits":2048},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				_ = e.POST("/pki").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusMethodNotAllowed)

			},
		},
		{
			name: "CreateCA CommonName&CaNameDifferent",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60 * 24
				enrollerTTL := 60 * 60
				req := fmt.Sprintf(`{"key_metadata":{"type":"RSA","bits":2048},"subject":{"common_name":"test2","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				_ = e.POST("/pki/test").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "CreateCA EnrollerTTL<CaTTL",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60
				enrollerTTL := 60 * 60 * 24
				req := fmt.Sprintf(`{"key_metadata":{"type":"RSA","bits":2048},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				_ = e.POST("/pki/test").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "CreateCA InvalidRSAKeyBits",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60
				enrollerTTL := 60 * 60 * 24
				req := fmt.Sprintf(`{"key_metadata":{"type":"RSA","bits":2044},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				_ = e.POST("/pki/test").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "CreateCA InvalidECDSAKeyBits",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60
				enrollerTTL := 60 * 60 * 24
				req := fmt.Sprintf(`{"key_metadata":{"type":"EC","bits":200},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				_ = e.POST("/pki/test").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "CreateCA InvalidJSONBody",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60 * 24
				enrollerTTL := 60 * 60
				req := fmt.Sprintf(`{"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				_ = e.POST("/pki/test").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "CreateCA ExistCAName",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60 * 24
				enrollerTTL := 60 * 60
				req := fmt.Sprintf(`{"key_metadata":{"type":"RSA","bits":2048},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				_ = e.POST("/pki/test").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusConflict)

			},
		},
		{
			name: "GetCert CertificateNotExist",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/pki/test/cert/12-04-12").
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "GetCert MissingSerialNumber",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/pki/test/cert/").
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "GetCert InvalidCaType",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/lamassu/test/cert/12-06-05").
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "ImportCA RSAKey",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				private_key := "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRRGpwTmc1KzdwNG5lcFoKK0dkNFRscWN5R1JENkpNdi9JYVJmenFGeXBJUlhMckN1M3FPL3JQbXd1RnVRMjBpbElMMEQ2T3BITXAxMUw1agpoSGpoNzJ6d2NXaXFBeFpWR0xSNE1Ja2hYUjJKN1ZoWVBXYUR1WWluNVYwSWtZV0tNeitibE94VGdVV0dOSDFsCmNLbm1lendDSDZQaHgvZjRCclJMcks3Um9FWS9lKzljb29kVS9VVVFhNVFscXRIZnBxa1o0Z1U3a3FUekFYMVAKQzdoNEozcUhiTkJEMCtSQ1FOMWdjaXNvcmc3UWs2QlQ4dWJZc0VkMGlVeWFheXlTOGpqMy9nQnhaNm44RTRrUgplRFY2ZFk1TFRKY1ZVMnFZTk9SMHUza0xVdGt4bHlRSlhaV2daRG1tNU1YdkNKTTE0L1VWa1NMcmpBdEFRb0RkCkQwa0NQWlNIQWdNQkFBRUNnZ0VBU1ZxUENuQWhNRWpDZ1dkWUFCNVBlSUhpUFRldVppSWJRcnNhb280WjcxcFEKRy92SmpGWnFwZ3RhRk92Sk9RRmVDVU1ZMjUrWlpjcTk1dGVERkZyUVlkSkpoYThrL1JyTzNJUFhURmJ5ODhUMQpXTW5BUk9YK01RdnBwSjh2eHM2b3ludDhnNVArVVRhTXlhazZOaml6cDRPR2pYU2daTjNVTHlaZjF0Q3NranZECnA0amIvb2hxaXlGRDE1ZjZVcDE1SzlPcld6eWwvYXIxTE1Ib1p6MWd4KytnZ2UwRll3bEJaVWJmUXF3aDZJMDcKNGNlRS93SEw4L3FUUUJIdkNiWXRLcWxLN092cnV0QlVwMVJuTTlKcllIVTZoUURiUDFLR0JsTzZmdGdCSWl1RApXVkt5Y21KQ2VZVFJ0NjNyc3AwOGliTXJHVHpvU1lFQ3NLWWMzVWpMb1FLQmdRRCtEcTBIN0owSWhOMUpmYXAvCm5ZNWVVcHVGaVlrS0lham9oQ2Qya01naGo4Ym9xb1FZazhWMGN6SDZJZFlsMXFzaFJ1SzkydGd4aGUrWjMvd1IKYk9tQ1lvZE50MU84WVNQOEk5MCsyMnFkdUtROWQ5WDAzMFQwNXpLWWs4VzdaZ0N1R2lSanlCSStBT1FzZ3BWRQpTSXBDc1BPdmdDYmxROFJBWjl5TGhiLzZxUUtCZ1FEbFluYTZUalg5T1RMbXlDYmxTNU81ZlFEdEpqNE9NYzNrCkppSzQxYURDY0xKdkR6NWxjTjVTdGs4WWNyY3NNdElwWWRSMTBSUW5CdnZ5ZGJYS1MvWlpiT3ZCdFI4bFF4N2gKOVdBRW01U1AvdHErTkNlQ1lFQzZJYVlPdUE5MHpyVWNvWXJ6WUtQR056eWRQNDIzNW5wUTkyVnBZSlQyK0lhSwpoNURqYVk5RHJ3S0JnRm4zaUg3TjQ2NG9udFJ2ay9rdEtrVnNxM1pXaGhqNFlvQTBqR1VJVUZiU08zWVpMRDRuCjFqeXVybndOajNCRzNNTWoveGVNY0JMWmcwZlNjY2taOEhjanZSWmdYVjdRWjVYYWZYYk03S3g5dm11bUREWnkKK2xCZnJ5TW84VlN6Z25vazk4MytBN2ZCU1F3YUVoSGtQbEh2cDl2MlhjL0NkN1QzRXJxMTJvNUJBb0dBVkpVNApQbjYwZmNsbnNaM0FhZkN5YWtWajRBNm45MGY2S2RTK0hQWDVMM21xOGpUbXh6VVZaZDUvei80TStTbE1RYUluClc4SmE4Z0VyU2o2SmFDMFdpK2NVRC91Zm5uZmZuV2FEbjI5WEdyblpJeVhNSTlFbVRQdzNaVm9OcVA3SDNlVGIKZmQ3MnhSSjlNV2JMOVRIeGpJV05TWXdwb2VBR2pISnN4TTZaMjFVQ2dZRUFucXlWbEtSZEdrVittUlVZSGoxeQo5YlRPM2F6YVh4dGF4WEZtRVI3RWpzNmVrcTR3a1lUMzNCMVJMRWVreUtMY2NDRkFaSW41YWhZY2M5YmtDK0MwCjR5L2JBWmcycHpNMVJXVHVJRkRlYW5wcWovOEJpMlFlOHJ6YVh3UE9zVjgvckZDWG5nN1VQN2hacWlnWnJ3MVgKaXlNWUNYeWhVaTI1aDQvRCthK2hpaEk9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0="
				cert := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURrVENDQW5tZ0F3SUJBZ0lVZHkydFhZcEd6RUU5ZEFoRUh3MmVySStiZE1Fd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1dERUxNQWtHQTFVRUJoTUNSVk14RXpBUkJnTlZCQWdNQ2xOdmJXVXRVM1JoZEdVeElUQWZCZ05WQkFvTQpHRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpERVJNQThHQTFVRUF3d0lTVzF3YjNKMFEwRXdIaGNOCk1qSXdOVEl6TURrek56STVXaGNOTWpNd05USXpNRGt6TnpJNVdqQllNUXN3Q1FZRFZRUUdFd0pGVXpFVE1CRUcKQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVoTUI4R0ExVUVDZ3dZU1c1MFpYSnVaWFFnVjJsa1oybDBjeUJRZEhrZwpUSFJrTVJFd0R3WURWUVFEREFoSmJYQnZjblJEUVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDCkFRb0NnZ0VCQU9PazJEbjd1bmlkNmxuNFozaE9XcHpJWkVQb2t5LzhocEYvT29YS2toRmN1c0s3ZW83K3MrYkMKNFc1RGJTS1VndlFQbzZrY3luWFV2bU9FZU9IdmJQQnhhS29ERmxVWXRIZ3dpU0ZkSFludFdGZzlab081aUtmbApYUWlSaFlvelA1dVU3Rk9CUllZMGZXVndxZVo3UEFJZm8rSEg5L2dHdEV1c3J0R2dSajk3NzF5aWgxVDlSUkJyCmxDV3EwZCttcVJuaUJUdVNwUE1CZlU4THVIZ25lb2RzMEVQVDVFSkEzV0J5S3lpdUR0Q1RvRlB5NXRpd1IzU0oKVEpwckxKTHlPUGYrQUhGbnFmd1RpUkY0TlhwMWprdE1seFZUYXBnMDVIUzdlUXRTMlRHWEpBbGRsYUJrT2Fiawp4ZThJa3pYajlSV1JJdXVNQzBCQ2dOMFBTUUk5bEljQ0F3RUFBYU5UTUZFd0hRWURWUjBPQkJZRUZHemY5djZICkQwQmVLM3ZnOHhuTUMraTEzaStMTUI4R0ExVWRJd1FZTUJhQUZHemY5djZIRDBCZUszdmc4eG5NQytpMTNpK0wKTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUc2Q2hCb200MUdZeFpxKwp3azNkV0hzYWczMlM4RnFvcG5LbkU5Vm92WFNrREh1WHZPMTk4bXFJaUhhNVAxbmR1N0Z4NkRKWElPTlhtRTNkCk1MaHFlM1JTREIyNVk0ZHh4NnEwWFZ6MjREY3lUNWN2RkRZamV0WDBaeHl1aUUxbE56M29TL0VIK1V1Y2g4MkcKL0NOdkxtUGVkV2wzZGhWMkhOeUsrMjhhY1dZM2VDcGEzb0xvdGdvUXNVR2VReTR4dnZ1YnVUWnpjc2FRSGxRWgp1MTA0UWdFYXhaRCs1MFE3UFVqUDAreks0UzVkYXhzb0RyM1hFWmdNbTkxcGpFUUg4cVkwdyszTnowVnhKT3RPClpmZkkxMFhEUlZmaHdqeHZuS29kS05xVkJ3dnRSZGIvQU1KL1psVlg0MzJyTkVDVUwrbXJhZi81S281U3NVT2sKWTd2SjVkbz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ=="
				enrollerTTL := 30 * 30
				req := fmt.Sprintf(`{"crt":"%s","private_key":"%s","enroller_ttl":%d}`, cert, private_key, enrollerTTL)
				obj := e.POST("/pki/import/ImportCA").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ValueEqual("status", "issued")
				obj.Object().ContainsKey("name")
				obj.Object().ContainsKey("serial_number")
				obj.Object().ContainsKey("subject")
				obj.Object().Value("subject").Object().ValueEqual("common_name", obj.Object().Value("name").String().Raw())
				obj.Object().ContainsKey("key_metadata")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")
			},
		},
		{
			name: "ImportCA InvalidJSONFormat",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				private_key := "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRRGpwTmc1KzdwNG5lcFoKK0dkNFRscWN5R1JENkpNdi9JYVJmenFGeXBJUlhMckN1M3FPL3JQbXd1RnVRMjBpbElMMEQ2T3BITXAxMUw1agpoSGpoNzJ6d2NXaXFBeFpWR0xSNE1Ja2hYUjJKN1ZoWVBXYUR1WWluNVYwSWtZV0tNeitibE94VGdVV0dOSDFsCmNLbm1lendDSDZQaHgvZjRCclJMcks3Um9FWS9lKzljb29kVS9VVVFhNVFscXRIZnBxa1o0Z1U3a3FUekFYMVAKQzdoNEozcUhiTkJEMCtSQ1FOMWdjaXNvcmc3UWs2QlQ4dWJZc0VkMGlVeWFheXlTOGpqMy9nQnhaNm44RTRrUgplRFY2ZFk1TFRKY1ZVMnFZTk9SMHUza0xVdGt4bHlRSlhaV2daRG1tNU1YdkNKTTE0L1VWa1NMcmpBdEFRb0RkCkQwa0NQWlNIQWdNQkFBRUNnZ0VBU1ZxUENuQWhNRWpDZ1dkWUFCNVBlSUhpUFRldVppSWJRcnNhb280WjcxcFEKRy92SmpGWnFwZ3RhRk92Sk9RRmVDVU1ZMjUrWlpjcTk1dGVERkZyUVlkSkpoYThrL1JyTzNJUFhURmJ5ODhUMQpXTW5BUk9YK01RdnBwSjh2eHM2b3ludDhnNVArVVRhTXlhazZOaml6cDRPR2pYU2daTjNVTHlaZjF0Q3NranZECnA0amIvb2hxaXlGRDE1ZjZVcDE1SzlPcld6eWwvYXIxTE1Ib1p6MWd4KytnZ2UwRll3bEJaVWJmUXF3aDZJMDcKNGNlRS93SEw4L3FUUUJIdkNiWXRLcWxLN092cnV0QlVwMVJuTTlKcllIVTZoUURiUDFLR0JsTzZmdGdCSWl1RApXVkt5Y21KQ2VZVFJ0NjNyc3AwOGliTXJHVHpvU1lFQ3NLWWMzVWpMb1FLQmdRRCtEcTBIN0owSWhOMUpmYXAvCm5ZNWVVcHVGaVlrS0lham9oQ2Qya01naGo4Ym9xb1FZazhWMGN6SDZJZFlsMXFzaFJ1SzkydGd4aGUrWjMvd1IKYk9tQ1lvZE50MU84WVNQOEk5MCsyMnFkdUtROWQ5WDAzMFQwNXpLWWs4VzdaZ0N1R2lSanlCSStBT1FzZ3BWRQpTSXBDc1BPdmdDYmxROFJBWjl5TGhiLzZxUUtCZ1FEbFluYTZUalg5T1RMbXlDYmxTNU81ZlFEdEpqNE9NYzNrCkppSzQxYURDY0xKdkR6NWxjTjVTdGs4WWNyY3NNdElwWWRSMTBSUW5CdnZ5ZGJYS1MvWlpiT3ZCdFI4bFF4N2gKOVdBRW01U1AvdHErTkNlQ1lFQzZJYVlPdUE5MHpyVWNvWXJ6WUtQR056eWRQNDIzNW5wUTkyVnBZSlQyK0lhSwpoNURqYVk5RHJ3S0JnRm4zaUg3TjQ2NG9udFJ2ay9rdEtrVnNxM1pXaGhqNFlvQTBqR1VJVUZiU08zWVpMRDRuCjFqeXVybndOajNCRzNNTWoveGVNY0JMWmcwZlNjY2taOEhjanZSWmdYVjdRWjVYYWZYYk03S3g5dm11bUREWnkKK2xCZnJ5TW84VlN6Z25vazk4MytBN2ZCU1F3YUVoSGtQbEh2cDl2MlhjL0NkN1QzRXJxMTJvNUJBb0dBVkpVNApQbjYwZmNsbnNaM0FhZkN5YWtWajRBNm45MGY2S2RTK0hQWDVMM21xOGpUbXh6VVZaZDUvei80TStTbE1RYUluClc4SmE4Z0VyU2o2SmFDMFdpK2NVRC91Zm5uZmZuV2FEbjI5WEdyblpJeVhNSTlFbVRQdzNaVm9OcVA3SDNlVGIKZmQ3MnhSSjlNV2JMOVRIeGpJV05TWXdwb2VBR2pISnN4TTZaMjFVQ2dZRUFucXlWbEtSZEdrVittUlVZSGoxeQo5YlRPM2F6YVh4dGF4WEZtRVI3RWpzNmVrcTR3a1lUMzNCMVJMRWVreUtMY2NDRkFaSW41YWhZY2M5YmtDK0MwCjR5L2JBWmcycHpNMVJXVHVJRkRlYW5wcWovOEJpMlFlOHJ6YVh3UE9zVjgvckZDWG5nN1VQN2hacWlnWnJ3MVgKaXlNWUNYeWhVaTI1aDQvRCthK2hpaEk9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0="
				cert := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURrVENDQW5tZ0F3SUJBZ0lVZHkydFhZcEd6RUU5ZEFoRUh3MmVySStiZE1Fd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1dERUxNQWtHQTFVRUJoTUNSVk14RXpBUkJnTlZCQWdNQ2xOdmJXVXRVM1JoZEdVeElUQWZCZ05WQkFvTQpHRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpERVJNQThHQTFVRUF3d0lTVzF3YjNKMFEwRXdIaGNOCk1qSXdOVEl6TURrek56STVXaGNOTWpNd05USXpNRGt6TnpJNVdqQllNUXN3Q1FZRFZRUUdFd0pGVXpFVE1CRUcKQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVoTUI4R0ExVUVDZ3dZU1c1MFpYSnVaWFFnVjJsa1oybDBjeUJRZEhrZwpUSFJrTVJFd0R3WURWUVFEREFoSmJYQnZjblJEUVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDCkFRb0NnZ0VCQU9PazJEbjd1bmlkNmxuNFozaE9XcHpJWkVQb2t5LzhocEYvT29YS2toRmN1c0s3ZW83K3MrYkMKNFc1RGJTS1VndlFQbzZrY3luWFV2bU9FZU9IdmJQQnhhS29ERmxVWXRIZ3dpU0ZkSFludFdGZzlab081aUtmbApYUWlSaFlvelA1dVU3Rk9CUllZMGZXVndxZVo3UEFJZm8rSEg5L2dHdEV1c3J0R2dSajk3NzF5aWgxVDlSUkJyCmxDV3EwZCttcVJuaUJUdVNwUE1CZlU4THVIZ25lb2RzMEVQVDVFSkEzV0J5S3lpdUR0Q1RvRlB5NXRpd1IzU0oKVEpwckxKTHlPUGYrQUhGbnFmd1RpUkY0TlhwMWprdE1seFZUYXBnMDVIUzdlUXRTMlRHWEpBbGRsYUJrT2Fiawp4ZThJa3pYajlSV1JJdXVNQzBCQ2dOMFBTUUk5bEljQ0F3RUFBYU5UTUZFd0hRWURWUjBPQkJZRUZHemY5djZICkQwQmVLM3ZnOHhuTUMraTEzaStMTUI4R0ExVWRJd1FZTUJhQUZHemY5djZIRDBCZUszdmc4eG5NQytpMTNpK0wKTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUc2Q2hCb200MUdZeFpxKwp3azNkV0hzYWczMlM4RnFvcG5LbkU5Vm92WFNrREh1WHZPMTk4bXFJaUhhNVAxbmR1N0Z4NkRKWElPTlhtRTNkCk1MaHFlM1JTREIyNVk0ZHh4NnEwWFZ6MjREY3lUNWN2RkRZamV0WDBaeHl1aUUxbE56M29TL0VIK1V1Y2g4MkcKL0NOdkxtUGVkV2wzZGhWMkhOeUsrMjhhY1dZM2VDcGEzb0xvdGdvUXNVR2VReTR4dnZ1YnVUWnpjc2FRSGxRWgp1MTA0UWdFYXhaRCs1MFE3UFVqUDAreks0UzVkYXhzb0RyM1hFWmdNbTkxcGpFUUg4cVkwdyszTnowVnhKT3RPClpmZkkxMFhEUlZmaHdqeHZuS29kS05xVkJ3dnRSZGIvQU1KL1psVlg0MzJyTkVDVUwrbXJhZi81S281U3NVT2sKWTd2SjVkbz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ=="
				enrollerTTL := 30 * 30
				req := fmt.Sprintf(`"crt":"%s","private_key":"%s","enroller_ttl":%d`, cert, private_key, enrollerTTL)
				_ = e.POST("/pki/import/ImportCA").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "ImportCA ECDSAKey",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				private_key := "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUszem95aFRuOVl1OGVNaUYrdU83cmh6OVExeXgvWmY0UHpYT1ZTSlJQSWRvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFcVJrcWIvaTY1anU5UGlEdUY1aUMyRktkNldTaWFESXdrSURlQXcyaW1wREpWUVl2UzlqOApNOWljZmNHdHZ3Nmo5Z0lWeUhoMk1Dd0ZYdmVFczlab2ZRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQ=="
				cert := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNCRENDQWF1Z0F3SUJBZ0lVTWM5eWhPM05IRThqZEZPblZWNG5IdHYwVjhJd0NnWUlLb1pJemowRUF3SXcKV0RFTE1Ba0dBMVVFQmhNQ1FWVXhFekFSQmdOVkJBZ01DbE52YldVdFUzUmhkR1V4SVRBZkJnTlZCQW9NR0VsdQpkR1Z5Ym1WMElGZHBaR2RwZEhNZ1VIUjVJRXgwWkRFUk1BOEdBMVVFQXd3SVNXMXdiM0owUTBFd0hoY05Nakl3Ck5USTJNRGswTnpVeFdoY05Nak13TlRJMk1EazBOelV4V2pCWU1Rc3dDUVlEVlFRR0V3SkJWVEVUTUJFR0ExVUUKQ0F3S1UyOXRaUzFUZEdGMFpURWhNQjhHQTFVRUNnd1lTVzUwWlhKdVpYUWdWMmxrWjJsMGN5QlFkSGtnVEhSawpNUkV3RHdZRFZRUUREQWhKYlhCdmNuUkRRVEJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCS2taCkttLzR1dVk3dlQ0ZzdoZVlndGhTbmVsa29tZ3lNSkNBM2dNTm9wcVF5VlVHTDB2WS9EUFluSDNCcmI4T28vWUMKRmNoNGRqQXNCVjczaExQV2FIMmpVekJSTUIwR0ExVWREZ1FXQkJSeGdUcGk2TFhMcXJxTk12Y0FiUFdYTExQLwpQakFmQmdOVkhTTUVHREFXZ0JSeGdUcGk2TFhMcXJxTk12Y0FiUFdYTExQL1BqQVBCZ05WSFJNQkFmOEVCVEFECkFRSC9NQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJRHlrVHZLejA2c0pndnRwaktDVkRleEwrK3dDWkp3bkd4Z3EKQ0Z6eVcvOHJBaUFKd05hV2o0aTY4clJrSEtJYXd4Mjh0anR2eCtpWnQ0N21zM2RscGZWS3B3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ=="
				enrollerTTL := 30 * 30
				req := fmt.Sprintf(`{"crt":"%s","private_key":"%s","enroller_ttl":%d}`, cert, private_key, enrollerTTL)
				obj := e.POST("/pki/import/ImportCA").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ValueEqual("status", "issued")
				obj.Object().ContainsKey("name")
				obj.Object().ContainsKey("serial_number")
				obj.Object().ContainsKey("subject")
				obj.Object().Value("subject").Object().ValueEqual("common_name", obj.Object().Value("name").String().Raw())
				obj.Object().ContainsKey("key_metadata")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")
			},
		},
		{
			name: "ImportCA ECDSA128InvalidKey",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				private_key := "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1FUUNBUUVFRUc2ZDlSengyN0F6YTBtdCt5dWdwb0dnQndZRks0RUVBQnloSkFNaUFBVEt1aG9tUXZ5UzhIc0sKUTduSjZ4YzVqZDRpUnpjV1BNUkxxUEh3MGVnSU93PT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQ=="
				cert := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ3akNDQVlpZ0F3SUJBZ0lVZU1CblQ0ZkhVWVk3NUxXazVJWUtsZEo3ck5zd0NnWUlLb1pJemowRUF3SXcKV0RFTE1Ba0dBMVVFQmhNQ1FWVXhFekFSQmdOVkJBZ01DbE52YldVdFUzUmhkR1V4SVRBZkJnTlZCQW9NR0VsdQpkR1Z5Ym1WMElGZHBaR2RwZEhNZ1VIUjVJRXgwWkRFUk1BOEdBMVVFQXd3SVNXMXdiM0owUTBFd0hoY05Nakl3Ck5USTJNVEV5TWpVMVdoY05Nak13TlRJMk1URXlNalUxV2pCWU1Rc3dDUVlEVlFRR0V3SkJWVEVUTUJFR0ExVUUKQ0F3S1UyOXRaUzFUZEdGMFpURWhNQjhHQTFVRUNnd1lTVzUwWlhKdVpYUWdWMmxrWjJsMGN5QlFkSGtnVEhSawpNUkV3RHdZRFZRUUREQWhKYlhCdmNuUkRRVEEyTUJBR0J5cUdTTTQ5QWdFR0JTdUJCQUFjQXlJQUJNcTZHaVpDCi9KTHdld3BEdWNuckZ6bU4zaUpITnhZOHhFdW84ZkRSNkFnN28xTXdVVEFkQmdOVkhRNEVGZ1FVTGlTemFQd3UKS3RqajZCblM3QWc1a2hBaTRJTXdId1lEVlIwakJCZ3dGb0FVTGlTemFQd3VLdGpqNkJuUzdBZzVraEFpNElNdwpEd1lEVlIwVEFRSC9CQVV3QXdFQi96QUtCZ2dxaGtqT1BRUURBZ01vQURBbEFoRUErd05Od0hBdUZGRGs3c0hNCmlZMHFOUUlRTVNzMlUzUVBZSEZkL252NDNjb05YZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="
				enrollerTTL := 30 * 30
				req := fmt.Sprintf(`{"crt":"%s","private_key":"%s","enroller_ttl":%d}`, cert, private_key, enrollerTTL)
				_ = e.POST("/pki/import/ImportCA").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "ImportCA RSA1024InvalidKey",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				private_key := "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlDWGdJQkFBS0JnUURUN1NlTWxwc2Y5VjFnVUZuVUlGYVpJRVB2RlQwRnc5TVkzZ2RLSktRNU9ad2ZDS3NOCmR1UVZHVHdoNUJNYngzT2ZsSUNJTU5aV2x5dWhHSUFCMVZLNlM2Q3JabWluQzNTMXNXRnFpN0tSM0NYaVFtVmUKb3hZb1RoTUE4YmQrL2lpMmw2VzZOZUVrVXpoN1V0bm1vNlZzMDRDRFNSV29aUjRtZnFVQWkxekxFUUlEQVFBQgpBb0dCQUx3ME8xQXVHN3NvOHZEcXlxdUl3SDhpV1ZKRW9UbXlhNUVFOUtKU29na3o4VUxhTnRZeFJHSzhVMXVoCnFacWM2VURKNTgrSzEzNTBwOGxiOGFvdklWUTBNVnIvSjVvZUh5QWVwTUJmNnNpa1QvNFZUWlBPOGozMEhPV3QKZXFCVUc1M1RmSTVoY1dMZUxPb2N2OVU4bkRJY05Nbm5kZHhCU2hwNldtc2Zjcm9WQWtFQTljcXViRWlTcUhudQp5L01OY3B2bzlOWHJOQ2lWMlN4d3Jzd3B5UVF5NUo2eFRtYS9WMWZSSGZpRGNpenNsUG9SMk9GMG4wMTVKZC9oCk9Ga1QzZ05QMHdKQkFOeTZhSkEyNG9vQndhSFZzdDhGeHBOazM4QTBTazA5Z0ZTeUVKa1dIYTI3SGhmdXBCcCsKZkZLNysrOUFzcDkybS9UOTJyWDV6U3dDM29TZjNtWnBEd3NDUVFEcWlXUzIzdWxTNmtiN1Jnbm0rdTduOGRobQpCUFE0THplM0ZBb3JUbDVoMlN2SGJEUFkzR3NtOWlRM3ByWjUwY1dGOWx5YVJncjhJUTEvL3ovOThac1JBa0FCCm5DSnpHdE5nS2s4ZFBRL0c3S1hjSVZvNGJxazBFd1RDbVdIaG0vV3ZkTFB0Zk1JWnAxNkV3L1k4Y241YkIyUnYKendJdlhaa1BmeDNjWGNZamZSU3RBa0VBdVZuMlJza0RUSit6OEd0NHFWVnZoRlIvcG4rRTdLK0NXNkpjNlMrbQpzQTErTFZpS1NscHloNlFoUFVSbkVmWTVOUlVmbERHdlFkSS9YYjMraXpkd1N3PT0KLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0="
				cert := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqRENDQWZXZ0F3SUJBZ0lVRjF2dXlCWmd2S1dTRzdrRDRtQU1LZGZvWkNVd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1dERUxNQWtHQTFVRUJoTUNRVlV4RXpBUkJnTlZCQWdNQ2xOdmJXVXRVM1JoZEdVeElUQWZCZ05WQkFvTQpHRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpERVJNQThHQTFVRUF3d0lTVzF3YjNKMFEwRXdIaGNOCk1qSXdOVEkyTVRFeE5qTTVXaGNOTWpNd05USTJNVEV4TmpNNVdqQllNUXN3Q1FZRFZRUUdFd0pCVlRFVE1CRUcKQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVoTUI4R0ExVUVDZ3dZU1c1MFpYSnVaWFFnVjJsa1oybDBjeUJRZEhrZwpUSFJrTVJFd0R3WURWUVFEREFoSmJYQnZjblJEUVRDQm56QU5CZ2txaGtpRzl3MEJBUUVGQUFPQmpRQXdnWWtDCmdZRUEwKzBuakphYkgvVmRZRkJaMUNCV21TQkQ3eFU5QmNQVEdONEhTaVNrT1RtY0h3aXJEWGJrRlJrOEllUVQKRzhkem41U0FpRERXVnBjcm9SaUFBZFZTdWt1Z3EyWm9wd3QwdGJGaGFvdXlrZHdsNGtKbFhxTVdLRTRUQVBHMwpmdjRvdHBlbHVqWGhKRk00ZTFMWjVxT2xiTk9BZzBrVnFHVWVKbjZsQUl0Y3l4RUNBd0VBQWFOVE1GRXdIUVlEClZSME9CQllFRkcrNlRHbjZ3MnNDNkVndjdoTGhDZE9RczVjNU1COEdBMVVkSXdRWU1CYUFGRys2VEduNncyc0MKNkVndjdoTGhDZE9RczVjNU1BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ1lFQQpoOTcxWENVMWZyMFp3U1pKTStaWStDZzQwSmxHT1FKUmxiT3I5S2phMHY1N3I5emgzNlVxTlhTQ2hLOW9wUW1UCkJuRnF1dC82Z3I0SVkyZ3oyZHhSSE5DNkVxWTc3NVhoeFE4RXpqbkRBd3ZPS3VEYmtScVVoMkZtcjZwOXpMcDAKbExZMUJmQkpqRlFLaCt6Q1JwZkN6SW9SQ2hxckJnUU1tL0ZuNUZBWXZJTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ=="
				enrollerTTL := 30 * 30
				req := fmt.Sprintf(`{"crt":"%s","private_key":"%s","enroller_ttl":%d}`, cert, private_key, enrollerTTL)
				_ = e.POST("/pki/import/ImportCA").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "ImportCA CertificateIsNotInBase64 ",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				private_key := "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRRGpwTmc1KzdwNG5lcFoKK0dkNFRscWN5R1JENkpNdi9JYVJmenFGeXBJUlhMckN1M3FPL3JQbXd1RnVRMjBpbElMMEQ2T3BITXAxMUw1agpoSGpoNzJ6d2NXaXFBeFpWR0xSNE1Ja2hYUjJKN1ZoWVBXYUR1WWluNVYwSWtZV0tNeitibE94VGdVV0dOSDFsCmNLbm1lendDSDZQaHgvZjRCclJMcks3Um9FWS9lKzljb29kVS9VVVFhNVFscXRIZnBxa1o0Z1U3a3FUekFYMVAKQzdoNEozcUhiTkJEMCtSQ1FOMWdjaXNvcmc3UWs2QlQ4dWJZc0VkMGlVeWFheXlTOGpqMy9nQnhaNm44RTRrUgplRFY2ZFk1TFRKY1ZVMnFZTk9SMHUza0xVdGt4bHlRSlhaV2daRG1tNU1YdkNKTTE0L1VWa1NMcmpBdEFRb0RkCkQwa0NQWlNIQWdNQkFBRUNnZ0VBU1ZxUENuQWhNRWpDZ1dkWUFCNVBlSUhpUFRldVppSWJRcnNhb280WjcxcFEKRy92SmpGWnFwZ3RhRk92Sk9RRmVDVU1ZMjUrWlpjcTk1dGVERkZyUVlkSkpoYThrL1JyTzNJUFhURmJ5ODhUMQpXTW5BUk9YK01RdnBwSjh2eHM2b3ludDhnNVArVVRhTXlhazZOaml6cDRPR2pYU2daTjNVTHlaZjF0Q3NranZECnA0amIvb2hxaXlGRDE1ZjZVcDE1SzlPcld6eWwvYXIxTE1Ib1p6MWd4KytnZ2UwRll3bEJaVWJmUXF3aDZJMDcKNGNlRS93SEw4L3FUUUJIdkNiWXRLcWxLN092cnV0QlVwMVJuTTlKcllIVTZoUURiUDFLR0JsTzZmdGdCSWl1RApXVkt5Y21KQ2VZVFJ0NjNyc3AwOGliTXJHVHpvU1lFQ3NLWWMzVWpMb1FLQmdRRCtEcTBIN0owSWhOMUpmYXAvCm5ZNWVVcHVGaVlrS0lham9oQ2Qya01naGo4Ym9xb1FZazhWMGN6SDZJZFlsMXFzaFJ1SzkydGd4aGUrWjMvd1IKYk9tQ1lvZE50MU84WVNQOEk5MCsyMnFkdUtROWQ5WDAzMFQwNXpLWWs4VzdaZ0N1R2lSanlCSStBT1FzZ3BWRQpTSXBDc1BPdmdDYmxROFJBWjl5TGhiLzZxUUtCZ1FEbFluYTZUalg5T1RMbXlDYmxTNU81ZlFEdEpqNE9NYzNrCkppSzQxYURDY0xKdkR6NWxjTjVTdGs4WWNyY3NNdElwWWRSMTBSUW5CdnZ5ZGJYS1MvWlpiT3ZCdFI4bFF4N2gKOVdBRW01U1AvdHErTkNlQ1lFQzZJYVlPdUE5MHpyVWNvWXJ6WUtQR056eWRQNDIzNW5wUTkyVnBZSlQyK0lhSwpoNURqYVk5RHJ3S0JnRm4zaUg3TjQ2NG9udFJ2ay9rdEtrVnNxM1pXaGhqNFlvQTBqR1VJVUZiU08zWVpMRDRuCjFqeXVybndOajNCRzNNTWoveGVNY0JMWmcwZlNjY2taOEhjanZSWmdYVjdRWjVYYWZYYk03S3g5dm11bUREWnkKK2xCZnJ5TW84VlN6Z25vazk4MytBN2ZCU1F3YUVoSGtQbEh2cDl2MlhjL0NkN1QzRXJxMTJvNUJBb0dBVkpVNApQbjYwZmNsbnNaM0FhZkN5YWtWajRBNm45MGY2S2RTK0hQWDVMM21xOGpUbXh6VVZaZDUvei80TStTbE1RYUluClc4SmE4Z0VyU2o2SmFDMFdpK2NVRC91Zm5uZmZuV2FEbjI5WEdyblpJeVhNSTlFbVRQdzNaVm9OcVA3SDNlVGIKZmQ3MnhSSjlNV2JMOVRIeGpJV05TWXdwb2VBR2pISnN4TTZaMjFVQ2dZRUFucXlWbEtSZEdrVittUlVZSGoxeQo5YlRPM2F6YVh4dGF4WEZtRVI3RWpzNmVrcTR3a1lUMzNCMVJMRWVreUtMY2NDRkFaSW41YWhZY2M5YmtDK0MwCjR5L2JBWmcycHpNMVJXVHVJRkRlYW5wcWovOEJpMlFlOHJ6YVh3UE9zVjgvckZDWG5nN1VQN2hacWlnWnJ3MVgKaXlNWUNYeWhVaTI1aDQvRCthK2hpaEk9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0="
				cert := "-----BEGIN CERTIFICATE-----MIIDkTCCAnmgAwIBAgIUdy2tXYpGzEE9dAhEHw2erI+bdMEwDQYJKoZIhvcNAQELBQAwWDELMAkGA1UEBhMCRVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDERMA8GA1UEAwwISW1wb3J0Q0EwHhcNMjIwNTIzMDkzNzI5WhcNMjMwNTIzMDkzNzI5WjBYMQswCQYDVQQGEwJFUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMREwDwYDVQQDDAhJbXBvcnRDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOOk2Dn7unid6ln4Z3hOWpzIZEPoky/8hpF/OoXKkhFcusK7eo7+s+bC4W5DbSKUgvQPo6kcynXUvmOEeOHvbPBxaKoDFlUYtHgwiSFdHYntWFg9ZoO5iKflXQiRhYozP5uU7FOBRYY0fWVwqeZ7PAIfo+HH9/gGtEusrtGgRj9771yih1T9RRBrlCWq0d+mqRniBTuSpPMBfU8LuHgneods0EPT5EJA3WByKyiuDtCToFPy5tiwR3SJTJprLJLyOPf+AHFnqfwTiRF4NXp1jktMlxVTapg05HS7eQtS2TGXJAldlaBkOabkxe8IkzXj9RWRIuuMC0BCgN0PSQI9lIcCAwEAAaNTMFEwHQYDVR0OBBYEFGzf9v6HD0BeK3vg8xnMC+i13i+LMB8GA1UdIwQYMBaAFGzf9v6HD0BeK3vg8xnMC+i13i+LMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAG6ChBom41GYxZq+wk3dWHsag32S8FqopnKnE9VovXSkDHuXvO198mqIiHa5P1ndu7Fx6DJXIONXmE3dMLhqe3RSDB25Y4dxx6q0XVz24DcyT5cvFDYjetX0ZxyuiE1lNz3oS/EH+Uuch82G/CNvLmPedWl3dhV2HNyK+28acWY3eCpa3oLotgoQsUGeQy4xvvubuTZzcsaQHlQZu104QgEaxZD+50Q7PUjP0+zK4S5daxsoDr3XEZgMm91pjEQH8qY0w+3Nz0VxJOtOZffI10XDRVfhwjxvnKodKNqVBwvtRdb/AMJ/ZlVX432rNECUL+mraf/5Ko5SsUOkY7vJ5do=-----END CERTIFICATE-----"
				enrollerTTL := 30 * 30
				req := fmt.Sprintf(`{"crt":"%s","private_key":"%s","enroller_ttl":%d}`, cert, private_key, enrollerTTL)
				_ = e.POST("/pki/import/ImportCA").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "DeleteCA WithIssuedCerts",
			serviceInitialization: func(s *service.Service) {
				data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0=")
				block, _ := pem.Decode([]byte(data))
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
				cert, _ := (*s).SignCertificate(ctx, dto.Pki, "test", *csr, true, csr.Subject.CommonName)
				data, _ = base64.StdEncoding.DecodeString(cert.Crt)
				block, _ = pem.Decode([]byte(data))
				x509Certificate, _ = x509.ParseCertificate(block.Bytes)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.DELETE("/pki/test").
					Expect().
					Status(http.StatusOK).JSON()

			},
		},
		{
			name: "GetCA StatusRevoked",
			serviceInitialization: func(s *service.Service) {
				data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0=")
				block, _ := pem.Decode([]byte(data))
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
				cert, _ := (*s).SignCertificate(ctx, dto.Pki, "test", *csr, true, csr.Subject.CommonName)
				data, _ = base64.StdEncoding.DecodeString(cert.Crt)
				block, _ = pem.Decode([]byte(data))
				x509Certificate, _ = x509.ParseCertificate(block.Bytes)
				(*s).DeleteCA(ctx, dto.Pki, "test")
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/pki").
					Expect().
					Status(http.StatusOK).JSON()

			},
		},
		{
			name: "DeleteCA InvalidCaName",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.DELETE("/pki/test").
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "DeleteCert",
			serviceInitialization: func(s *service.Service) {
				data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0=")
				block, _ := pem.Decode([]byte(data))
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
				cert, _ := (*s).SignCertificate(ctx, dto.Pki, "test", *csr, true, csr.Subject.CommonName)
				data, _ = base64.StdEncoding.DecodeString(cert.Crt)
				block, _ = pem.Decode([]byte(data))
				x509Certificate, _ = x509.ParseCertificate(block.Bytes)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.DELETE("/pki/test/cert/" + utils.InsertNth(utils.ToHexInt(x509Certificate.SerialNumber), 2)).
					Expect().
					Status(http.StatusOK).JSON()

			},
		},

		{
			name: "DeleteCert InvalidCaType",
			serviceInitialization: func(s *service.Service) {
				data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0=")
				block, _ := pem.Decode([]byte(data))
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
				cert, _ := (*s).SignCertificate(ctx, dto.Pki, "test", *csr, true, csr.Subject.CommonName)
				data, _ = base64.StdEncoding.DecodeString(cert.Crt)
				block, _ = pem.Decode([]byte(data))
				x509Certificate, _ = x509.ParseCertificate(block.Bytes)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.DELETE("/lamassu/test/cert/" + utils.InsertNth(utils.ToHexInt(x509Certificate.SerialNumber), 2)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "DeleteCert CertificateAlreadyRevoked",
			serviceInitialization: func(s *service.Service) {
				data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0=")
				block, _ := pem.Decode([]byte(data))
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
				cert, _ := (*s).SignCertificate(ctx, dto.Pki, "test", *csr, true, csr.Subject.CommonName)
				data, _ = base64.StdEncoding.DecodeString(cert.Crt)
				block, _ = pem.Decode([]byte(data))
				x509Certificate, _ = x509.ParseCertificate(block.Bytes)
				(*s).DeleteCert(ctx, dto.Pki, "test", utils.InsertNth(utils.ToHexInt(x509Certificate.SerialNumber), 2))
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.DELETE("/pki/test/cert/" + utils.InsertNth(utils.ToHexInt(x509Certificate.SerialNumber), 2)).
					Expect().
					Status(http.StatusPreconditionFailed)

			},
		},
		{
			name: "GetCert",
			serviceInitialization: func(s *service.Service) {

				data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0=")
				block, _ := pem.Decode([]byte(data))
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
				cert, _ := (*s).SignCertificate(ctx, dto.Pki, "test", *csr, true, csr.Subject.CommonName)
				data, _ = base64.StdEncoding.DecodeString(cert.Crt)
				block, _ = pem.Decode([]byte(data))
				x509Certificate, _ = x509.ParseCertificate(block.Bytes)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/pki/test/cert/" + utils.InsertNth(utils.ToHexInt(x509Certificate.SerialNumber), 2)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ValueEqual("status", "issued")
				obj.Object().ContainsKey("name")
				obj.Object().ContainsKey("serial_number")
				obj.Object().ContainsKey("certificate")
				obj.Object().ContainsKey("subject")
				obj.Object().ContainsKey("key_metadata")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")

			},
		},
		{
			name: "GetIssuedCert",
			serviceInitialization: func(s *service.Service) {
				data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0=")
				block, _ := pem.Decode([]byte(data))
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
				(*s).SignCertificate(ctx, dto.Pki, "test", *csr, true, csr.Subject.CommonName)

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/pki/test/issued").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().Value("total_certs").Equal(1)
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("serial_number")
				obj.Object().Value("certs").Array().Element(0).Object().ValueEqual("status", "issued")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("subject")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("key_metadata")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("certificate")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("name")

			},
		},
		{
			name: "GetIssuedCert Filters",
			serviceInitialization: func(s *service.Service) {
				data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0=")
				block, _ := pem.Decode([]byte(data))
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
				(*s).SignCertificate(ctx, dto.Pki, "test", *csr, true, csr.Subject.CommonName)

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/pki/test/issued").WithQuery("s", "{ASC,id}").WithQuery("page", "{1,15}").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().Value("total_certs").Equal(1)
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("serial_number")
				obj.Object().Value("certs").Array().Element(0).Object().ValueEqual("status", "issued")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("subject")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("key_metadata")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("certificate")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("name")

			},
		},
		{
			name: "GetIssuedCert FiltersEmpty",
			serviceInitialization: func(s *service.Service) {
				data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0=")
				block, _ := pem.Decode([]byte(data))
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
				(*s).SignCertificate(ctx, dto.Pki, "test", *csr, true, csr.Subject.CommonName)

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/pki/test/issued").WithQuery("s", "{}").WithQuery("page", "{}").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().Value("total_certs").Equal(1)
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("serial_number")
				obj.Object().Value("certs").Array().Element(0).Object().ValueEqual("status", "issued")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("subject")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("key_metadata")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("certificate")
				obj.Object().Value("certs").Array().Element(0).Object().ContainsKey("name")

			},
		},
		{
			name: "GetIssuedCert InvalidCaType",
			serviceInitialization: func(s *service.Service) {
				data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0=")
				block, _ := pem.Decode([]byte(data))
				csr, _ := x509.ParseCertificateRequest(block.Bytes)
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
				(*s).SignCertificate(ctx, dto.Pki, "test", *csr, true, csr.Subject.CommonName)

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/lamassu/test/issued").WithQueryString("s={ASC,id}&page={1,15}").
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "SignCertificate",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				csrString := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0="
				req := fmt.Sprintf(`{"csr":"%s","sign_verbatim":true}`, csrString)
				obj := e.POST("/pki/test/sign").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("crt")

			},
		},
		{
			name: "SignCertificate False",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				csrString := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0="
				req := fmt.Sprintf(`{"csr":"%s","sign_verbatim":false}`, csrString)
				obj := e.POST("/pki/test/sign").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("crt")

			},
		},
		{
			name: "SignCertificate InvalidJSONFormat",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				csrString := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1l6Q0NBVXNDQVFBd0hqRUxNQWtHQTFVRUJoTUNSVk14RHpBTkJnTlZCQU1NQmtSbGRtbGpaVENDQVNJdwpEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTHZqZ1dEdWZtZ2kxY2VsVTk1N2RlYnpnSUZDCnBCN2xWTHNYQ2M2RFNoVW1sNmVDOHAxbllPMVJyNmkyNFlOQkRsRmtyZCt6YVJNTWs2NFlXYVgvK0VUTFQ2WmkKSkdIK242VUhyd01aSFliajh3M1UzRDQ5aG9WYjNRVWtrNm9VUExSV2NGQmd2UU5CTzNTRWx3RzdqWTg1dHFIUQpudlQxVkdYeW40dE9ac3Q1bHJZbWxmMGFjZmg4MlMzU3ZVVURKL24wY056Ynh2ME84MFhjUUFCbm16WlROWHVPCjVTc084clg4NnBwclhMcEFTKzZ0OWpqemNLZ296MnJpUHJXeXMzT2cvckpsM2dLWDdSNXBLUWUzMkFkNUJVblcKTkpvZ0kxMVFBcVdRSTB1YWpaSHFPbXl5Y0dGbi9FMC9BR240YlErOUVrblVRSzFMSHRkL0tVRXVNeWNDQXdFQQpBYUFBTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCam9aSzJPaHhIZ3FFVjBnVmFVUG1sUzBUbnl3RXYvcjMxCnk5R3lXOUZ3a3VVd3Rka3V2VHFVZE1TcUorUjIxZTNzTnhxRWtaamovKytVS09wdDFuTnZOb2kxakNsS0ZDZXgKc3M4ajdsdHhvL28yeld2aVVDcmE1cWNlV0NLajJyMWhnd2pKa0w5YjhrSTExWjdRVFhrRlhvVE9wTjFnYlZSVQo1MEdkeGkwNDNkTi9xdk1nMHkyUWxLV3ZFSE5MZTlTRVRqb3RJR3dyclYvLzlXNXlVTDRwY1ZhMGlML0ZsdUpXCnFXZExZVkl4MXZYOUM4alJ4RHAzZVZ4STR1UldYMkEycEV0ckcvYlpTbDZzc2JuU0lzZXJGaXZ2UEt5K0kyNzcKQ0RyNWwyT0hQTHNmWTJBNjl4aEExMXNLRU5RN2dHc1FLSjA5WG55NjF5ZlVRNitIYzQ2NAotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0="
				req := fmt.Sprintf(`"csr":"%s","sign_verbatim":true`, csrString)
				_ = e.POST("/pki/test/sign").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "SignCertificate InvalidBody",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dto.Subject{CommonName: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				csrString := "-----BEGIN CERTIFICATE REQUEST-----MIICYzCCAUsCAQAwHjELMAkGA1UEBhMCRVMxDzANBgNVBAMMBkRldmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALvjgWDufmgi1celU957debzgIFCpB7lVLsXCc6DShUml6eC8p1nYO1Rr6i24YNBDlFkrd+zaRMMk64YWaX/+ETLT6ZiJGH+n6UHrwMZHYbj8w3U3D49hoVb3QUkk6oUPLRWcFBgvQNBO3SElwG7jY85tqHQnvT1VGXyn4tOZst5lrYmlf0acfh82S3SvUUDJ/n0cNzbxv0O80XcQABnmzZTNXuO5SsO8rX86pprXLpAS+6t9jjzcKgoz2riPrWys3Og/rJl3gKX7R5pKQe32Ad5BUnWNJogI11QAqWQI0uajZHqOmyycGFn/E0/AGn4bQ+9EknUQK1LHtd/KUEuMycCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBjoZK2OhxHgqEV0gVaUPmlS0TnywEv/r31y9GyW9FwkuUwtdkuvTqUdMSqJ+R21e3sNxqEkZjj/++UKOpt1nNvNoi1jClKFCexss8j7ltxo/o2zWviUCra5qceWCKj2r1hgwjJkL9b8kI11Z7QTXkFXoTOpN1gbVRU50Gdxi043dN/qvMg0y2QlKWvEHNLe9SETjotIGwrrV//9W5yUL4pcVa0iL/FluJWqWdLYVIx1vX9C8jRxDp3eVxI4uRWX2A2pEtrG/bZSl6ssbnSIserFivvPKy+I277CDr5l2OHPLsfY2A69xhA11sKENQ7gGsQKJ09Xny61yfUQ6+Hc464-----END CERTIFICATE REQUEST-----"
				req := fmt.Sprintf(`{"csr":"%s","sign_verbatim":true}`, csrString)
				_ = e.POST("/pki/test/sign").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var logger log.Logger
			logger = log.NewJSONLogger(os.Stdout)
			logger = level.NewFilter(logger, level.AllowDebug())
			logger = log.With(logger, "ts", log.DefaultTimestampUTC)
			logger = log.With(logger, "caller", log.DefaultCaller)

			vaultClient, _ := mocks.NewVaultSecretsMock(t)
			vaultSecret, err := vault.NewVaultSecretsWithClient(
				vaultClient, "", "pki/lamassu/dev/", "", "", "", "", "", logger,
			)
			if err != nil {
				t.Fatal("Unable to create Vault in-memory service")
			}

			caDBInstance, _ := mocks.NewCasDBMock(t)
			tracer := opentracing.NoopTracer{}

			s := service.NewCAService(logger, vaultSecret, caDBInstance)

			handler := MakeHTTPHandler(s, logger, tracer)
			server := httptest.NewServer(handler)
			defer server.Close()

			tc.serviceInitialization(&s)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}
