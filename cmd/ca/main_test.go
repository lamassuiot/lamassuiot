package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/mocks"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/secrets/vault"
	"github.com/opentracing/opentracing-go"

	"github.com/gavv/httpexpect/v2"
)

func TestCAHandler(t *testing.T) {

	tt := []struct {
		name                  string
		serviceInitialization func(s *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
	}{
		{
			name: "Get CAs",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				(*s).CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "rsa", KeyBits: 4096}, dto.Subject{CN: "test"}, 60*60*24, 60*60)
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/pki").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Array().Length().Equal(1)
				obj.Array().Element(0).Object().ContainsKey("status")
				obj.Array().Element(0).Object().ContainsKey("name")
				obj.Array().Element(0).Object().ContainsKey("serial_number")
				obj.Array().Element(0).Object().ContainsKey("subject")
				obj.Array().Element(0).Object().ContainsKey("key_metadata")
				obj.Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("type")
			},
		},
		{
			name: "Create CA",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				caTTL := 60 * 60 * 24
				enrollerTTL := 60 * 60
				ca := fmt.Sprintf(`{"key_metadata":{"type":"rsa","bits":2048},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"ca_ttl":%d,"enroller_ttl":%d}`, caTTL, enrollerTTL)
				fmt.Println(ca)
				obj := e.POST("/pki/test").WithBytes([]byte(ca)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("status")

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

			handler := transport.MakeHTTPHandler(s, logger, tracer)
			server := httptest.NewServer(handler)
			defer server.Close()

			tc.serviceInitialization(&s)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)
		})
	}
}
