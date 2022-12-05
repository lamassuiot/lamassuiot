package transport

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gavv/httpexpect/v2"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service/outputchannels"
	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	caService "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	testUtils "github.com/lamassuiot/lamassuiot/pkg/utils/test/utils"
)

type TestCase struct {
	name                  string
	serviceInitialization func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context
	testRestEndpoint      func(ctx context.Context, e *httpexpect.Expect)
}

func TestHealth(t *testing.T) {

	tt := []TestCase{
		{
			name: "CorrectHealth",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
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

func TestSubscribe(t *testing.T) {

	tt := []TestCase{
		{
			name: "CorrectSubscribe_EmptyCondition",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBody := `{"email":"ehernandez@ikerlan.es","event_type":"io.lamassuiot.ca.create" }`

				obj := e.POST("/v1/subscribe").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				subscriptionsObj := obj.Object().Value("subscriptions").Array().First()
				subscriptionsObj.Object().ContainsMap(map[string]interface{}{

					"channel": map[string]interface{}{
						"config": nil,
						"name":   "",
						"type":   "",
					},
					"conditions": nil,
					"event_type": "io.lamassuiot.ca.create",
					"user_id":    "",
					"condition_type": nil,
				})

			},
		},
		{
			name: "CorrectSubscribe_NonEmptyCondition",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBody := `{"email":"ehernandez@ikerlan.es","event_type":"io.lamassuiot.ca.create" }`

				obj := e.POST("/v1/subscribe").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				subscriptionsObj := obj.Object().Value("subscriptions").Array().First()
				subscriptionsObj.Object().ContainsMap(map[string]interface{}{

					"channel": map[string]interface{}{
						"config": nil,
						"name":   "",
						"type":   "",
					},
					"conditions": nil,
					"event_type": "io.lamassuiot.ca.create",
					"user_id":    "",
					"condition_type": "data.name",
				})

			},
		},
		{
			name: "InvalidJSON_Subscribe",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBody := `{"email":`

				e.POST("/v1/subscribe").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "BadRequest_Subscribe",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_ = e.POST("/v1/subscribe/").WithBytes([]byte(nil)).
					Expect().
					Status(http.StatusBadRequest)
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

func TestGetSubscriptions(t *testing.T) {

	tt := []TestCase{
		{
			name: "CorrectGetUserSubscriptions",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				_, err := (*svc).SubscribedEvent(ctx, &api.SubscribeEventInput{
					EventType:  "io.lamassuiot.ca.create",
					Conditions: nil,
					Channel:    api.ChannelCreation{Type: "", Name: "", Config: nil},
					UserID:     "1",
				})

				if err != nil {
					t.Errorf("%s", err)
				}
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {

				obj := e.GET("/v1/subscriptions/1").
					Expect().
					Status(http.StatusOK).JSON()

				subscriptionsObj := obj.Object().Value("subscriptions").Array().First()
				subscriptionsObj.Object().ContainsMap(map[string]interface{}{

					"channel": map[string]interface{}{
						"config": nil,
						"name":   "",
						"type":   "",
					},
					"conditions": nil,
					"event_type": "io.lamassuiot.ca.create",
					"user_id":    "1",
				})

			},
		},
		{
			name: "NoUser_GetUserSubscriptions",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				e.GET("/v1/subscriptions/123").
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

var temp string

func TestUnsubscribe(t *testing.T) {

	tt := []TestCase{
		{
			name: "CorrectUnsubscribe",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {

				_, err := (*svc).SubscribedEvent(ctx, &api.SubscribeEventInput{
					EventType:  "io.lamassuiot.ca.create",
					Conditions: nil,
					Channel:    api.ChannelCreation{Type: "", Name: "", Config: nil},
					UserID:     "1",
				})

				if err != nil {
					t.Errorf("%s", err)
				}
				_, err = (*svc).SubscribedEvent(ctx, &api.SubscribeEventInput{
					EventType:  "io.lamassuiot.ca.update",
					Conditions: nil,
					Channel:    api.ChannelCreation{Type: "", Name: "", Config: nil},
					UserID:     "1",
				})

				if err != nil {
					t.Errorf("%s", err)
				}

				subsOut, err := (*svc).GetSubscriptions(context.Background(), &api.GetSubscriptionsInput{
					UserID: "1",
				})
				temp = subsOut.Subscriptions[0].ID

				if err != nil {
					t.Errorf("%s", err)
				}
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {

				reqBody := `{"user_id":"1","subscription_id":"` + temp + `"}`

				obj := e.POST("/v1/unsubscribe").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusOK).JSON()

				subscriptionsObj := obj.Object().Value("subscriptions").Array().First()
				subscriptionsObj.Object().ContainsMap(map[string]interface{}{

					"channel": map[string]interface{}{
						"config": nil,
						"name":   "",
						"type":   "",
					},
					"conditions": nil,
					"event_type": "io.lamassuiot.ca.update",
					"user_id":    "1",
				})

			},
		},
		{
			name: "BadRequest_Unsubscribe",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				_ = e.POST("/v1/unsubscribe").WithBytes([]byte(nil)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "ErrMissingUserId_Unsubscribe",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBody := `{"user_id":"","subscription_id":"132"}`

				e.POST("/v1/unsubscribe").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "InvalidJSON_Unsubscribe",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBody := `{"user_id":`

				e.POST("/v1/unsubscribe").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "ErrMissingConnectorID_Unsubscribe",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBody := `{"user_id":"123","subscription_id":""}`

				e.POST("/v1/unsubscribe").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "NotFound_Unsubscribe",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBody := `{"user_id":"123","subscription_id":"46545"}`

				e.POST("/v1/unsubscribe/").WithBytes([]byte(reqBody)).
					Expect().
					Status(http.StatusNotFound)
			},
		},
		{
			name: "NoUser_Unsubscribe",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {
				reqBody := `{"user_id":"123","subscription_id":"46545"}`

				e.POST("/v1/unsubscribe").WithBytes([]byte(reqBody)).
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

func TestGetEvents(t *testing.T) {

	tt := []TestCase{
		{
			name: "GetEvents_CreateCA",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service) context.Context {
				_, err := (*svc).SubscribedEvent(ctx, &api.SubscribeEventInput{
					EventType:  "io.lamassuiot.ca.create",
					Conditions: nil,
					Channel:    api.ChannelCreation{Type: "", Name: "", Config: nil},
					UserID:     "1",
				})

				if err != nil {
					t.Errorf("%s", err)
				}

				_, err = (*svcCA).CreateCA(context.Background(), &caApi.CreateCAInput{
					CAType: caApi.CATypePKI,
					Subject: caApi.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: caApi.KeyMetadata{
						KeyType: caApi.RSA,
						KeyBits: 4096,
					},
					CADuration:       time.Hour * 5,
					IssuanceDuration: time.Hour,
				})

				if err != nil {
					t.Errorf("%s", err)
				}

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, e *httpexpect.Expect) {

				//TODO: pasar el event como input?
				obj := e.GET("/v1/lastevents").
					Expect().
					Status(http.StatusOK).JSON()
				obj.Raw()
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

	smtpConfig := outputchannels.SMTPOutputService{
		Host:              "172.16.255.146",
		Port:              25,
		Username:          "",
		Password:          "",
		From:              "lamassu-alerts@ikerlan.es",
		SSL:               true,
		Insecure:          true,
		EmailTemplateFile: "/home/ikerlan/lamassu/lamassuiot/pkg/alerts/server/resources/email.html",
	}

	serverCA, caSvc, err := testUtils.BuildCATestServer()
	if err != nil {
		t.Errorf("%s", err)
	}
	defer serverCA.Close()
	serverCA.Start()

	serverAlerts, svc, err := testUtils.BuildMailTestServer("/home/ikerlan/lamassu/lamassuiot/pkg/alerts/server/resources/config.json", smtpConfig)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer serverAlerts.Close()
	serverAlerts.Start()
	ctx = tc.serviceInitialization(ctx, svc, caSvc)
	e := httpexpect.New(t, serverAlerts.URL)
	tc.testRestEndpoint(ctx, e)

}
