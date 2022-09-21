package transport

// import (
// 	"context"
// 	"net/http"
// 	"testing"

// 	"github.com/gavv/httpexpect/v2"
// 	alertsService "github.com/lamassuiot/lamassuiot/pkg/mail/server/api/service"
// 	testUtils "github.com/lamassuiot/lamassuiot/pkg/utils/test/utils"
// )

// type TestCase struct {
// 	name                  string
// 	serviceInitialization func(ctx context.Context, s *alertsService.Service) context.Context
// 	testRestEndpoint      func(ctx context.Context, e *httpexpect.Expect)
// }

// func TestHealth(t *testing.T) {

// 	tt := []TestCase{
// 		{
// 			name: "CorrectHealth",
// 			serviceInitialization: func(ctx context.Context, svc *alertsService.Service) context.Context {
// 				return ctx
// 			},
// 			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
// 				obj := e.GET("/v1/health").
// 					Expect().
// 					Status(http.StatusOK).JSON()
// 				obj.Object().ContainsKey("healthy")
// 			},
// 		},
// 	}

// 	for _, tc := range tt {
// 		t.Run(tc.name, func(t *testing.T) {
// 			runTests(t, tc)
// 		})
// 	}
// }

// func runTests(t *testing.T, tc TestCase) {
// 	ctx := context.Background()

// 	serverMailManager, svcMailManager, err := testUtils.BuildMailTestServer("", "", "")
// 	if err != nil {
// 		t.Fatalf("%s", err)
// 	}
// 	defer serverMailManager.Close()
// 	ctx = tc.serviceInitialization(ctx, svcMailManager)

// 	//s = alertsService.NewalertsService(mainServer.Logger, mailRepo, "config.EmailFrom", "config.TemplateHTML", "config.TemplateJSON")

// }
