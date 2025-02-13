package assemblers

import (
	"context"
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	outputchannels "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services/alerts/output_channels"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestManageSuscriptions(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "alerts").WithEventBus().WithService(ALERTS).Build(t)
	if err != nil {
		t.Fatalf("could not create test service: %s", err)
	}

	alertsTest := serverTest.Alerts

	user1Subs, err := alertsTest.Service.Subscribe(context.TODO(),
		&services.SubscribeInput{
			UserID:    "user1",
			EventType: models.EventCreateCAKey,
			Channel: models.Channel{
				Type: models.ChannelTypeWebhook,
				Name: "webhook",
				Config: models.WebhookChannelConfig{
					WebhookURL: "http://localhost:8080"}},
		})
	if err != nil {
		t.Fatalf("could not subscribe user1: %s", err)
	}
	user1SubsId := user1Subs[0].ID

	user2Subs, err := alertsTest.Service.Subscribe(context.TODO(),
		&services.SubscribeInput{
			UserID:    "user2",
			EventType: models.EventCreateCAKey,
			Channel: models.Channel{
				Type: models.ChannelTypeWebhook,
				Name: "webhook",
				Config: models.WebhookChannelConfig{
					WebhookURL: "http://localhost:8080"}},
		})
	if err != nil {
		t.Fatalf("could not subscribe user2: %s", err)
	}

	user2SubsId := user2Subs[0].ID

	_, err = alertsTest.Service.Subscribe(context.TODO(),
		&services.SubscribeInput{
			UserID:    "user2",
			EventType: models.EventCreateDMSKey,
			Channel: models.Channel{
				Type: models.ChannelTypeWebhook,
				Name: "webhook",
				Config: models.WebhookChannelConfig{
					WebhookURL: "http://localhost:8080"}},
		})
	if err != nil {
		t.Fatalf("could not subscribe user2: %s", err)
	}

	subscriptions, err := alertsTest.Service.GetUserSubscriptions(context.TODO(), &services.GetUserSubscriptionsInput{UserID: "user1"})
	if err != nil {
		t.Fatalf("could not get subscriptions for user1: %s", err)
	}
	assert.Equal(t, 1, len(subscriptions), "user1 should have 1 subscription")

	subscriptions, err = alertsTest.Service.GetUserSubscriptions(context.TODO(), &services.GetUserSubscriptionsInput{UserID: "user2"})
	if err != nil {
		t.Fatalf("could not get subscriptions for user2: %s", err)
	}
	assert.Equal(t, 2, len(subscriptions), "user2 should have 2 subscription")

	// Unsubscribe
	alertsTest.Service.Unsubscribe(context.TODO(), &services.UnsubscribeInput{UserID: "user1", SubscriptionID: user1SubsId})
	subscriptions, err = alertsTest.Service.GetUserSubscriptions(context.TODO(), &services.GetUserSubscriptionsInput{UserID: "user1"})
	if err != nil {
		t.Fatalf("could not get subscriptions for user1: %s", err)
	}
	assert.Equal(t, 0, len(subscriptions), "user1 should have 0 subscription")

	alertsTest.Service.Unsubscribe(context.TODO(), &services.UnsubscribeInput{UserID: "user2", SubscriptionID: user2SubsId})

	subscriptions, err = alertsTest.Service.GetUserSubscriptions(context.TODO(), &services.GetUserSubscriptionsInput{UserID: "user2"})
	if err != nil {
		t.Fatalf("could not get subscriptions for user1: %s", err)
	}
	assert.Equal(t, 1, len(subscriptions), "user1 should have 1 subscription")

}

func TestGetLastEvents(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "alerts").WithEventBus().WithService(ALERTS).Build(t)
	if err != nil {
		t.Fatalf("could not create test service: %s", err)
	}

	alertsTest := serverTest.Alerts
	eventSamples, err := alertsTest.Service.GetLatestEventsPerEventType(context.TODO(), &services.GetLatestEventsPerEventTypeInput{})
	if err != nil {
		t.Fatalf("could not get latest events: %s", err)
	}
	assert.Equal(t, 0, len(eventSamples), "should have 0 events")

	eventType := models.EventCreateCAKey
	eventSource := "test://source"
	payload := map[string]string{"key": "value"}
	event := helpers.BuildCloudEvent(string(eventType), eventSource, payload)

	err = alertsTest.Service.HandleEvent(context.TODO(), &services.HandleEventInput{Event: event})
	if err != nil {
		t.Fatalf("could not handle event: %s", err)
	}

	err = alertsTest.Service.HandleEvent(context.TODO(), &services.HandleEventInput{Event: event})
	if err != nil {
		t.Fatalf("could not handle event: %s", err)
	}

	eventSamples, err = alertsTest.Service.GetLatestEventsPerEventType(context.TODO(), &services.GetLatestEventsPerEventTypeInput{})
	if err != nil {
		t.Fatalf("could not get latest events: %s", err)
	}
	assert.Equal(t, 1, len(eventSamples), "should have 1 events")
	assert.Equal(t, eventType, eventSamples[0].EventType, "should have the same event type")

	event = helpers.BuildCloudEvent(string(models.EventCreateDMSKey), eventSource, payload)
	err = alertsTest.Service.HandleEvent(context.TODO(), &services.HandleEventInput{Event: event})
	if err != nil {
		t.Fatalf("could not handle event: %s", err)
	}
	eventSamples, err = alertsTest.Service.GetLatestEventsPerEventType(context.TODO(), &services.GetLatestEventsPerEventTypeInput{})
	if err != nil {
		t.Fatalf("could not get latest events: %s", err)
	}
	assert.Equal(t, 2, len(eventSamples), "should have 2 events")
}

func setupMockOutputChannel(mock *MockOutputService) {

	builder := func(c models.Channel, smtpServer config.SMTPServer) (outputchannels.NotificationSenderService, error) {
		return mock, nil
	}
	outputchannels.RegisterOutputServiceBuilder(models.ChannelType("MOCK"), builder)
}

type MockOutputService struct {
	mock.Mock
}

func (m *MockOutputService) SendNotification(ctx context.Context, event cloudevents.Event) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func TestSubscriptionWithJSONPathFilter(t *testing.T) {

	outChannelMock := new(MockOutputService)

	outChannelMock.On("SendNotification", mock.Anything, mock.Anything).Return(nil)

	setupMockOutputChannel(outChannelMock)
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "alerts").WithEventBus().WithService(ALERTS).Build(t)
	if err != nil {
		t.Fatalf("could not create test service: %s", err)
	}

	alertsTest := serverTest.Alerts

	alertsTest.Service.Subscribe(context.TODO(),
		&services.SubscribeInput{
			UserID:    "user1",
			EventType: models.EventCreateCAKey,
			Channel: models.Channel{
				Type: models.ChannelType("MOCK"),
			},
			Conditions: []models.SubscriptionCondition{
				{
					Condition: "$.[?(@.name == 'John')]",
					Type:      models.JSONPath,
				},
			},
		},
	)

	eventType := models.EventCreateCAKey
	eventSource := "test://source"
	payload := map[string]interface{}{"person": map[string]interface{}{"name": "James", "age": "30"}}
	event := helpers.BuildCloudEvent(string(eventType), eventSource, payload)

	err = alertsTest.Service.HandleEvent(context.TODO(), &services.HandleEventInput{Event: event})
	if err != nil {
		t.Fatalf("could not handle event: %s", err)
	}
	outChannelMock.AssertNotCalled(t, "SendNotification", mock.Anything, mock.Anything)

	payload = map[string]interface{}{"person": map[string]interface{}{"name": "John", "age": "30"}}
	event = helpers.BuildCloudEvent(string(eventType), eventSource, payload)

	err = alertsTest.Service.HandleEvent(context.TODO(), &services.HandleEventInput{Event: event})
	if err != nil {
		t.Fatalf("could not handle event: %s", err)
	}

	mock.AssertExpectationsForObjects(t, outChannelMock)
}

func TestSubscriptionWithJSONSchemaFilter(t *testing.T) {

	outChannelMock := new(MockOutputService)

	outChannelMock.On("SendNotification", mock.Anything, mock.Anything).Return(nil)

	setupMockOutputChannel(outChannelMock)
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "alerts").WithEventBus().WithService(ALERTS).Build(t)
	if err != nil {
		t.Fatalf("could not create test service: %s", err)
	}
	alertsTest := serverTest.Alerts

	schema := `{
   "$schema":"https://json-schema.org/draft/2020-12/schema",
   "type":"object",
   "properties":{
      "person":{
	     "type": "object",
         "properties":{
            "name":{
               "const":"John"
            }
         },
         "required":[
            "name"
         ]
       }
   	  }
	}`

	alertsTest.Service.Subscribe(context.TODO(),
		&services.SubscribeInput{
			UserID:    "user1",
			EventType: models.EventCreateCAKey,
			Channel: models.Channel{
				Type: models.ChannelType("MOCK"),
			},
			Conditions: []models.SubscriptionCondition{
				{
					Condition: schema,
					Type:      models.JSONSchema,
				},
			},
		},
	)

	eventType := models.EventCreateCAKey
	eventSource := "test://source"
	payload := map[string]interface{}{"person": map[string]interface{}{"name": "James", "age": "30"}}
	event := helpers.BuildCloudEvent(string(eventType), eventSource, payload)

	err = alertsTest.Service.HandleEvent(context.TODO(), &services.HandleEventInput{Event: event})
	if err != nil {
		t.Fatalf("could not handle event: %s", err)
	}
	outChannelMock.AssertNotCalled(t, "SendNotification", mock.Anything, mock.Anything)

	payload = map[string]interface{}{"person": map[string]interface{}{"name": "John", "age": "30"}}
	event = helpers.BuildCloudEvent(string(eventType), eventSource, payload)

	err = alertsTest.Service.HandleEvent(context.TODO(), &services.HandleEventInput{Event: event})
	if err != nil {
		t.Fatalf("could not handle event: %s", err)
	}

	mock.AssertExpectationsForObjects(t, outChannelMock)
}
