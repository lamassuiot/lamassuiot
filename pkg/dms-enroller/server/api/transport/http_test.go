package transport

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/mocks"
	"github.com/opentracing/opentracing-go"

	"github.com/gavv/httpexpect/v2"
)

func TestDMSHandler(t *testing.T) {
	//var ca dto.Cert
	var dms dto.DMS
	tt := []struct {
		name                  string
		serviceInitialization func(s *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name: "GetDMSs InvalidPath",
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
				_ = e.GET("/v1/health").
					Expect().
					Status(http.StatusOK).JSON()

			},
		},
		{
			name: "GetDMSs DBIsEmpty",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/v1/").
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "GetDMSs",
			serviceInitialization: func(s *service.Service) {
				var cas []string
				cas = append(cas, "CA")
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")
				(*s).UpdateDMSStatus(ctx, "APPROVED", dms.Id, cas)

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Array().Length().Equal(1)
				obj.Array().Element(0).Object().ValueEqual("status", "APPROVED")
				obj.Array().Element(0).Object().ContainsKey("name")
				obj.Array().Element(0).Object().ContainsKey("key_metadata")
				obj.Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("type")
			},
		},
		{
			name: "GetDMSbyID DmsNotExist",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.GET("/v1/1234-1234").
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "GetDMSbyID",
			serviceInitialization: func(s *service.Service) {
				var cas []string
				cas = append(cas, "CA")
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")
				(*s).UpdateDMSStatus(ctx, "APPROVED", dms.Id, cas)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/" + dms.Id).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ValueEqual("status", "APPROVED")
				obj.Object().ContainsKey("name")
				obj.Object().ContainsKey("key_metadata")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")
			},
		},
		{
			name: "CreateDMS InvalidRSAKeyBits",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"key_metadata":{"type":"RSA","bits":2024},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"name":"test"}`)
				_ = e.POST("/v1/test/form").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "CreateDMS InvalidECDSAKeyBits",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"key_metadata":{"type":"EC","bits":200},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"name":"test"}`)
				_ = e.POST("/v1/test/form").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "CreateDMS InvalidBody",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"key_metadata":{"type":"RSA","bits":2048}}`)
				_ = e.POST("/v1/test/form").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "CreateDMS RSA",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"key_metadata":{"type":"RSA","bits":2048},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"name":"test"}`)
				obj := e.POST("/v1/test/form").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("dms")
				obj.Object().ContainsKey("priv_key")

				obj.Object().Value("dms").Object().ContainsKey("status").ValueEqual("status", "PENDING_APPROVAL")
				obj.Object().Value("dms").Object().ContainsKey("name")
				obj.Object().Value("dms").Object().ContainsKey("key_metadata")
				obj.Object().Value("dms").Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("dms").Object().Value("key_metadata").Object().ContainsKey("type")

			},
		},
		{
			name: "CreateDMS ECDSA224",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"key_metadata":{"type":"EC","bits":224},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"name":"test"}`)
				obj := e.POST("/v1/test/form").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("dms")
				obj.Object().ContainsKey("priv_key")

				obj.Object().Value("dms").Object().ContainsKey("status").ValueEqual("status", "PENDING_APPROVAL")
				obj.Object().Value("dms").Object().ContainsKey("name")
				obj.Object().Value("dms").Object().ContainsKey("key_metadata")
				obj.Object().Value("dms").Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("dms").Object().Value("key_metadata").Object().ContainsKey("type")

			},
		},
		{
			name: "CreateDMS ECDSA256",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"key_metadata":{"type":"EC","bits":256},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"name":"test"}`)
				obj := e.POST("/v1/test/form").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("dms")
				obj.Object().ContainsKey("priv_key")

				obj.Object().Value("dms").Object().ContainsKey("status").ValueEqual("status", "PENDING_APPROVAL")
				obj.Object().Value("dms").Object().ContainsKey("name")
				obj.Object().Value("dms").Object().ContainsKey("key_metadata")
				obj.Object().Value("dms").Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("dms").Object().Value("key_metadata").Object().ContainsKey("type")

			},
		},
		{
			name: "CreateDMS ECDSA384",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"key_metadata":{"type":"EC","bits":384},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"name":"test"}`)
				obj := e.POST("/v1/test/form").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("dms")
				obj.Object().ContainsKey("priv_key")

				obj.Object().Value("dms").Object().ContainsKey("status").ValueEqual("status", "PENDING_APPROVAL")
				obj.Object().Value("dms").Object().ContainsKey("name")
				obj.Object().Value("dms").Object().ContainsKey("key_metadata")
				obj.Object().Value("dms").Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("dms").Object().Value("key_metadata").Object().ContainsKey("type")

			},
		},
		{
			name: "CreateDMS InvalidJSON",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`"key_metadata":{"type":"RSA","bits":2048},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"name":"test"`)
				_ = e.POST("/v1/test/form").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "ImportDMS RSAKey",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				csrString := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1pUQ0NBVTBDQVFBd0lERUxNQWtHQTFVRUJoTUNSVk14RVRBUEJnTlZCQU1NQ0ZSbGMzUXRSRTFUTUlJQgpJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdkxMUFdTZlAybHdLbWhwK2ZrU1FWTEpUClZFTDBsdXQxblFJZW1BdVE0dkZ4WFZiOVJJYW1tZHMyajZaK3NVdGY5UklIYmZNOVRKdDBnUFAweUJ2bG11V3IKU1hsOEVaVDE1RlJrc2JlWk1ZL212S3RjU055Q040RXNmK2V5dXVxUGhydGt0QVdGZHVORW1maUJ1NzBUNnI3ZwpEb0E2dkQvTldiWTh4T1dMaHFNbldhVWE4Q3MyTEZ0NlNzc1JaZi9VakcrUUs2eDBoSDRyMkZtN2VITmNyWmo3CjNmam05dUhUb0t2Mm1tdkVkaUFWZklYYkEzZnl2ZHhaejlsekk4TGtLc2c5TWZydGJMNHZVNzZVMlR0TjRRYXIKWW9qb3Y2clZHdjN3TVJIR00vbVFmK2F4QXMwTWxPWVBpblFNNDFwNzFncmJmaGg5elJEd1kwampMUGJuL1FJRApBUUFCb0FBd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFJMHlJdVdLQXpHR3ROQWd4NWRuK0p4M1lzWXd0d3crClR1NG95WjVvbWJPRndQZWpyWndJSUg3ZmRWRmY5OFV5RDJSczkxaHFwdG12cFRTaUJrTjZ4UEdhakw1TVhUcUgKdmRFTFBDN0w0SUx5Z0t1ZnhxcjcwMnc0MllTV01aT2VwUXhZNTB6cG5DeG9YNmVHUFlwUVkxTVkrWXhvTjduVwplUVk1WUZSdmtqaTRhUjNLVVR3bElBTTJjbldHWFZsYkVBTWFadExVaGJYNVZjZTJSMkVzM0VLN1FZN3ZhVm5XCllncXdNMnkwbHg5bjdFVWxyNS9vUVl4M1VseWk1T0hrVm15OERKSldDbFFPVFdISVI4WkFHOXVYZTNTRGJtTTUKcnJYYjdzZWtHcTYwaDc1REJNY3FiakdRZE9MUks2bWRvbW9WNTA0TG54Y2dDaUEvSEMwTWYwST0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t"
				req := fmt.Sprintf(`{"csr":"%s"}`, csrString)
				obj := e.POST("/v1/test-DMS").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("csr")
				obj.Object().ContainsKey("status").ValueEqual("status", "PENDING_APPROVAL")
				obj.Object().ContainsKey("name")
				obj.Object().ContainsKey("key_metadata")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")

			},
		},
		{
			name: "ImportDMS ECDSAKey",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				csrString := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQkVqQ0J1Z0lCQURCWU1Rc3dDUVlEVlFRR0V3SkZVekVUTUJFR0ExVUVDQXdLVTI5dFpTMVRkR0YwWlRFaApNQjhHQTFVRUNnd1lTVzUwWlhKdVpYUWdWMmxrWjJsMGN5QlFkSGtnVEhSa01SRXdEd1lEVlFRRERBaDBaWE4wCkxVUk5VekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRjgyWVRxVll4L1Q3RWVjQ25rSW5HRlEKRkprYmNGYW9HM0VmY0xKUjgzb0tjM25XT2lEWjZNSDAzb244SHJTbDdFbEZkVXh6RSsvR0pNUVpMYWtQSVJtZwpBREFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUE1WVA4czJaNTE1SStxdllHTjkyT0VtSDVJbCs1Mmhjc01ZcUJkClhZNnB4d0lnQkUxcUs3WUZoQnVkWnFzSFRyakU2WnR6WTZMNWdDUjkrMS8wUEczUEQwcz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t"
				req := fmt.Sprintf(`{"csr":"%s"}`, csrString)
				obj := e.POST("/v1/test-DMS").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("csr")
				obj.Object().ContainsKey("status").ValueEqual("status", "PENDING_APPROVAL")
				obj.Object().ContainsKey("name")
				obj.Object().ContainsKey("key_metadata")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")

			},
		},
		{
			name: "ImportDMS InvalidJSON",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				csrString := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1pUQ0NBVTBDQVFBd0lERUxNQWtHQTFVRUJoTUNSVk14RVRBUEJnTlZCQU1NQ0ZSbGMzUXRSRTFUTUlJQgpJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdkxMUFdTZlAybHdLbWhwK2ZrU1FWTEpUClZFTDBsdXQxblFJZW1BdVE0dkZ4WFZiOVJJYW1tZHMyajZaK3NVdGY5UklIYmZNOVRKdDBnUFAweUJ2bG11V3IKU1hsOEVaVDE1RlJrc2JlWk1ZL212S3RjU055Q040RXNmK2V5dXVxUGhydGt0QVdGZHVORW1maUJ1NzBUNnI3ZwpEb0E2dkQvTldiWTh4T1dMaHFNbldhVWE4Q3MyTEZ0NlNzc1JaZi9VakcrUUs2eDBoSDRyMkZtN2VITmNyWmo3CjNmam05dUhUb0t2Mm1tdkVkaUFWZklYYkEzZnl2ZHhaejlsekk4TGtLc2c5TWZydGJMNHZVNzZVMlR0TjRRYXIKWW9qb3Y2clZHdjN3TVJIR00vbVFmK2F4QXMwTWxPWVBpblFNNDFwNzFncmJmaGg5elJEd1kwampMUGJuL1FJRApBUUFCb0FBd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFJMHlJdVdLQXpHR3ROQWd4NWRuK0p4M1lzWXd0d3crClR1NG95WjVvbWJPRndQZWpyWndJSUg3ZmRWRmY5OFV5RDJSczkxaHFwdG12cFRTaUJrTjZ4UEdhakw1TVhUcUgKdmRFTFBDN0w0SUx5Z0t1ZnhxcjcwMnc0MllTV01aT2VwUXhZNTB6cG5DeG9YNmVHUFlwUVkxTVkrWXhvTjduVwplUVk1WUZSdmtqaTRhUjNLVVR3bElBTTJjbldHWFZsYkVBTWFadExVaGJYNVZjZTJSMkVzM0VLN1FZN3ZhVm5XCllncXdNMnkwbHg5bjdFVWxyNS9vUVl4M1VseWk1T0hrVm15OERKSldDbFFPVFdISVI4WkFHOXVYZTNTRGJtTTUKcnJYYjdzZWtHcTYwaDc1REJNY3FiakdRZE9MUks2bWRvbW9WNTA0TG54Y2dDaUEvSEMwTWYwST0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t"
				req := fmt.Sprintf(`"csr":"%s"`, csrString)
				_ = e.POST("/v1/test-DMS").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},

		{
			name: "ImportDMS CsrIsNotInBase64",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				csrString := "-----BEGIN CERTIFICATE REQUEST-----MIICZTCCAU0CAQAwIDELMAkGA1UEBhMCRVMxETAPBgNVBAMMCFRlc3QtRE1TMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvLLPWSfP2lwKmhp+fkSQVLJTVEL0lut1nQIemAuQ4vFxXVb9RIammds2j6Z+sUtf9RIHbfM9TJt0gPP0yBvlmuWrSXl8EZT15FRksbeZMY/mvKtcSNyCN4Esf+eyuuqPhrtktAWFduNEmfiBu70T6r7gDoA6vD/NWbY8xOWLhqMnWaUa8Cs2LFt6SssRZf/UjG+QK6x0hH4r2Fm7eHNcrZj73fjm9uHToKv2mmvEdiAVfIXbA3fyvdxZz9lzI8LkKsg9MfrtbL4vU76U2TtN4QarYojov6rVGv3wMRHGM/mQf+axAs0MlOYPinQM41p71grbfhh9zRDwY0jjLPbn/QIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAI0yIuWKAzGGtNAgx5dn+Jx3YsYwtww+Tu4oyZ5ombOFwPejrZwIIH7fdVFf98UyD2Rs91hqptmvpTSiBkN6xPGajL5MXTqHvdELPC7L4ILygKufxqr702w42YSWMZOepQxY50zpnCxoX6eGPYpQY1MY+YxoN7nWeQY5YFRvkji4aR3KUTwlIAM2cnWGXVlbEAMaZtLUhbX5Vce2R2Es3EK7QY7vaVnWYgqwM2y0lx9n7EUlr5/oQYx3Ulyi5OHkVmy8DJJWClQOTWHIR8ZAG9uXe3SDbmM5rrXb7sekGq60h75DBMcqbjGQdOLRK6mdomoV504LnxcgCiA/HC0Mf0I=-----END CERTIFICATE REQUEST-----"
				req := fmt.Sprintf(`{"csr":"%s"}`, csrString)
				_ = e.POST("/v1/test-DMS").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "UpdateDmsStatus ApprovedDMS",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"authorized_cas":["CA"],"status":"APPROVED"}`)
				obj := e.PUT("/v1/" + dms.Id).WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("status").ValueEqual("status", "APPROVED")
				obj.Object().ContainsKey("name")
				obj.Object().ContainsKey("serial_number")
				obj.Object().ContainsKey("key_metadata")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")

			},
		},
		{
			name: "UpdateDmsStatus InvalidDmsID",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"authorized_cas":["CA"],"status":"APPROVED"}`)
				_ = e.PUT("/v1/3234").WithBytes([]byte(req)).
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "UpdateDmsStatus InvalidJSON",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`"authorized_cas":["CA"],"status":"APPROVED"`)
				_ = e.PUT("/v1/" + dms.Id).WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "UpdateDmsStatus StatusEmpty",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"authorized_cas":["CA"],"status":""}`)
				_ = e.PUT("/v1/" + dms.Id).WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "UpdateDmsStatus InvalidBody",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"status":"APPROVED"}`)
				_ = e.PUT("/v1/" + dms.Id).WithBytes([]byte(req)).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "UpdateDmsStatus DmsAlreadyApproved",
			serviceInitialization: func(s *service.Service) {
				var cas []string
				cas = append(cas, "CA")
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")
				(*s).UpdateDMSStatus(ctx, "APPROVED", dms.Id, cas)

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"authorized_cas":["CA"],"status":"APPROVED"}`)
				_ = e.PUT("/v1/" + dms.Id).WithBytes([]byte(req)).
					Expect().
					Status(http.StatusPreconditionFailed)

			},
		},
		{
			name: "UpdateDmsStatus DmsStatusIsNotApproved",
			serviceInitialization: func(s *service.Service) {
				var cas []string
				cas = append(cas, "CA")
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"status":"REVOKED"}`)
				_ = e.PUT("/v1/" + dms.Id).WithBytes([]byte(req)).
					Expect().
					Status(http.StatusPreconditionFailed)

			},
		},
		{
			name: "UpdateDmsStatus StatusReqIsPendingApproval",
			serviceInitialization: func(s *service.Service) {
				var cas []string
				cas = append(cas, "CA")
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"status":"PENDING_APPROVAL"}`)
				_ = e.PUT("/v1/" + dms.Id).WithBytes([]byte(req)).
					Expect().
					Status(http.StatusPreconditionFailed)

			},
		},
		{
			name: "UpdateDmsStatus DmsStatusIsNotPendingProvision",
			serviceInitialization: func(s *service.Service) {
				var cas []string
				cas = append(cas, "CA")
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")
				(*s).UpdateDMSStatus(ctx, "APPROVED", dms.Id, cas)

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"status":"DENIED"}`)
				_ = e.PUT("/v1/" + dms.Id).WithBytes([]byte(req)).
					Expect().
					Status(http.StatusPreconditionFailed)

			},
		},
		{
			name: "UpdateDmsStatus RejectDMS",
			serviceInitialization: func(s *service.Service) {
				var cas []string
				cas = append(cas, "CA")
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"status":"DENIED"}`)
				obj := e.PUT("/v1/" + dms.Id).WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("status").ValueEqual("status", "DENIED")
				obj.Object().ContainsKey("name")
				obj.Object().ContainsKey("key_metadata")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")

			},
		},
		{
			name: "UpdateDmsStatus RevokeDMS",
			serviceInitialization: func(s *service.Service) {
				var cas []string
				cas = append(cas, "CA")
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")
				(*s).UpdateDMSStatus(ctx, "APPROVED", dms.Id, cas)

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"status":"REVOKED"}`)
				obj := e.PUT("/v1/" + dms.Id).WithBytes([]byte(req)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("status").ValueEqual("status", "REVOKED")
				obj.Object().ContainsKey("name")
				obj.Object().ContainsKey("serial_number")
				obj.Object().ContainsKey("key_metadata")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")
			},
		},
		{
			name: "ApprovedDMS AuthCADuplicate",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				req := fmt.Sprintf(`{"authorized_cas":["CA","CA"],"status":"APPROVED"}`)
				_ = e.PUT("/v1/" + dms.Id).WithBytes([]byte(req)).
					Expect().
					Status(http.StatusConflict)

			},
		},
		{
			name: "DeleteDMS StatusIsPendingProvision",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.DELETE("/v1/" + dms.Id).
					Expect().
					Status(http.StatusPreconditionFailed)
			},
		},
		{
			name: "DeleteDMS InvalidDmsID",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.DELETE("/v1/123-456").
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "DeleteDMS DmsStatusRevoked",
			serviceInitialization: func(s *service.Service) {
				var cas []string
				cas = append(cas, "CA")
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")
				(*s).UpdateDMSStatus(ctx, "APPROVED", dms.Id, cas)
				(*s).UpdateDMSStatus(ctx, "REVOKED", dms.Id, nil)

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.DELETE("/v1/" + dms.Id).
					Expect().
					Status(http.StatusOK).JSON()
			},
		},
		{
			name: "DeleteDMS",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				_, dms, _ = (*s).CreateDMSForm(ctx, dto.Subject{CN: "test"}, dto.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test")
				(*s).UpdateDMSStatus(ctx, "DENIED", dms.Id, nil)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				_ = e.DELETE("/v1/" + dms.Id).
					Expect().
					Status(http.StatusOK).JSON()
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

			dmsdb, _ := mocks.NewDB(t)
			lamassuCaClient, _ := mocks.NewLamassuCaClientMock(logger)

			tracer := opentracing.NoopTracer{}

			s := service.NewEnrollerService(dmsdb, &lamassuCaClient, logger)

			handler := MakeHTTPHandler(s, logger, tracer)
			server := httptest.NewServer(handler)
			defer server.Close()

			tc.serviceInitialization(&s)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}
