package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/mocks"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/secrets/vault"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/opentracing/opentracing-go"
)

type testInput struct {
	method  string
	url     string
	payload string
}

type comparisonType int

const (
	Equal comparisonType = iota
	JSONLike
)

type testOutput struct {
	statusCode     int
	comparisonType comparisonType
	body           string
}

func TestPizzasHandler(t *testing.T) {

	tt := []struct {
		name  string
		input testInput
		want  testOutput
	}{
		{
			name: "Get CAs",
			input: testInput{
				method:  http.MethodGet,
				url:     "/pki",
				payload: "",
			},
			want: testOutput{
				statusCode:     http.StatusOK,
				comparisonType: JSONLike,
				body:           `[{"status":"issued","serial_number":"02-80-64-f7-a2-19-21-cf-b7-91-ce-22-d3-87-fe-08-ab-5e-79-5c","name":"test","key_metadata":{"type":"RSA","bits":2048,"strength":"medium"},"subject":{"common_name":"test","organization":"","organization_unit":"","country":"","state":"","locality":""},"certificate":{"pem_base64":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURRRENDQWlpZ0F3SUJBZ0lVQW9Cazk2SVpJYysza2M0aTA0ZitDS3RlZVZ3d0RRWUpLb1pJaHZjTkFRRUwKQlFBd0R6RU5NQXNHQTFVRUF4TUVkR1Z6ZERBZUZ3MHlNakExTWpJeE5qVTFNamxhRncwek1qQXpNekF4TmpVMQpOVGxhTUE4eERUQUxCZ05WQkFNVEJIUmxjM1F3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLCkFvSUJBUURGcGZNSEk4ckV1TW5FTHE4bHpNZXdRMnZJNzZua2RjWkdmalpCbndJNVU4NXBlZjF4Nmg2aUY4N2EKVER4RTVpQWYvSGZaWmJJdVlEYkk3b2NPWTdmcUIrcnVsMDZMYnhaSUZ3bFdzRXJSb1NXVVdCWi9uOHhZbHlEaQpTWndPM2E4UFI4T2RndWV0NFpGMFN3b3Y4OWgyM0V0UCtNcUgzcUNiSzJQdnhuTENBOGczVi9jM0laU1lLTWJuCmRnWkVyVDl4dkxJZHZZTjVEcTNreU5PQ0crN3RoWWdEVjdJOUVHN2ZpT2lrWUNpYWluQ2psb3V5RlVZZ2dlNmsKNmE4NEN1YU5vak16SjROZUJaclZJU1VOQ3ZXU0ZBSDNETitQeTIzcGlLemJhOFBCazFoS1RNQXAwdHFySWNBaQpEUk1yQ3dTMUd1RVBkVnJMZW9hZFFUazA3cnViQWdNQkFBR2pnWk13Z1pBd0RnWURWUjBQQVFIL0JBUURBZ0VHCk1BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZEbjRZZHJOKzBjL21TYlIrd2ZKWkpYVGY5Q2kKTUI4R0ExVWRJd1FZTUJhQUZEbjRZZHJOKzBjL21TYlIrd2ZKWkpYVGY5Q2lNQndHQ0NzR0FRVUZCd0VCQkJBdwpEakFNQmdnckJnRUZCUWN3QVlZQU1BOEdBMVVkRVFRSU1BYUNCSFJsYzNRd0RRWUpLb1pJaHZjTkFRRUxCUUFECmdnRUJBTFZ6VTRrQmZHelJueTZvM1dEbElGaHA3MDZZUktZNzYxdFNtOEFpT0JTY0JVRURpLzZlNUc2YThBckUKQ2FLNWFZSlVFcWxOYjFwOTg3aWVCcDNWSU1UZXV6OHZSRVk0ZmM1NlM0ZUh6c1Q1THNmaW1IQXI4ZEUxNUpVTgo4YnZNWUpOaDkrT2J3MzVOU0h2dHJMOThIaTFiRlVOUTE4eDE0eW5WRUJCd3o0Yy9OYmdVN2FTNHBXKytQTGdyCnNZRzl3akJpdE41blRxRExGUDlGVmdocm1qQzNRakh0Z0Z6ZkpZd0xLSVZSaElJZ0FORW5teWcwdjNwR2RRL24Kb1c3RzNJakxiWE5BbE5UakJVMVMvZ3EwbE4rRjB0T2x3YkZkZFRDQ3VGL0ZLaEs1SCtxU2RJWEg0eGpXSTNQMwp4Z3dhNnJ1SjlHNnFMVERSaHlwRThReXdNZjg9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0=","public_key_base64":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4YVh6QnlQS3hMakp4QzZ2SmN6SApzRU5yeU8rcDVIWEdSbjQyUVo4Q09WUE9hWG45Y2VvZW9oZk8ya3c4Uk9ZZ0gveDMyV1d5TG1BMnlPNkhEbU8zCjZnZnE3cGRPaTI4V1NCY0pWckJLMGFFbGxGZ1dmNS9NV0pjZzRrbWNEdDJ2RDBmRG5ZTG5yZUdSZEVzS0wvUFkKZHR4TFQvaktoOTZnbXl0ajc4Wnl3Z1BJTjFmM055R1VtQ2pHNTNZR1JLMC9jYnl5SGIyRGVRNnQ1TWpUZ2h2dQo3WVdJQTFleVBSQnUzNGpvcEdBb21vcHdvNWFMc2hWR0lJSHVwT212T0FybWphSXpNeWVEWGdXYTFTRWxEUXIxCmtoUUI5d3pmajh0dDZZaXMyMnZEd1pOWVNrekFLZExhcXlIQUlnMFRLd3NFdFJyaEQzVmF5M3FHblVFNU5PNjcKbXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="},"valid_from":"2022-05-22 16:55:29 +0000 UTC","valid_to":"2032-03-30 16:55:59 +0000 UTC"}]`,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.input.method, tc.input.url, strings.NewReader(tc.input.payload))
			responseRecorder := httptest.NewRecorder()

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
			ctx := context.Background()
			ctx = context.WithValue(ctx, utils.LamassuLoggerContextKey, logger)

			s.CreateCA(ctx, dto.Pki, "test", dto.PrivateKeyMetadata{KeyType: "rsa"}, dto.Subject{CN: "test"}, 60*60*24, 60*60)

			handler := transport.MakeHTTPHandler(s, logger, tracer)
			handler.ServeHTTP(responseRecorder, request)

			if responseRecorder.Code != tc.want.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.want.statusCode, responseRecorder.Code)
			}

			if tc.want.comparisonType == Equal {
				if strings.TrimSpace(responseRecorder.Body.String()) != tc.want.body {
					t.Errorf("Want '%s', got '%s'", tc.want.body, responseRecorder.Body)
				}
			} else if tc.want.comparisonType == JSONLike {
				var actualResponse []map[string]interface{}
				var wantedResponse []map[string]interface{}

				json.Unmarshal(responseRecorder.Body.Bytes(), &actualResponse)
				json.Unmarshal([]byte(tc.want.body), &wantedResponse)

				fmt.Println(responseRecorder.Body.String())

			}
		})
	}
}
