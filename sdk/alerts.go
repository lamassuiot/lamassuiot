package sdk

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type httpAlertsClient struct {
	httpClient *http.Client
	baseUrl    string
}

func (cli *httpAlertsClient) GetLatestEventsPerEventType(ctx context.Context, input *services.GetLatestEventsPerEventTypeInput) ([]*models.AlertLatestEvent, error) {
	url := cli.baseUrl + "/v1/events/latest"
	results := make([]*models.AlertLatestEvent, 0)
	_, err := IterGet[models.AlertLatestEvent, *resources.GetItemsResponse[models.AlertLatestEvent]](ctx, cli.httpClient, url, true, nil,
		func(ale models.AlertLatestEvent) {
			results = append(results, &ale)
		}, map[int][]error{})

	return results, err
}

func (cli *httpAlertsClient) GetUserSubscriptions(ctx context.Context, input *services.GetUserSubscriptionsInput) ([]*models.Subscription, error) {
	url := fmt.Sprintf("%s/v1/user/%s/subscriptions", cli.baseUrl, input.UserID)
	results := make([]*models.Subscription, 0)
	_, err := IterGet[models.Subscription, *resources.GetItemsResponse[models.Subscription]](ctx, cli.httpClient, url, true, nil,
		func(ale models.Subscription) {
			results = append(results, &ale)
		}, map[int][]error{})
	return results, err
}

func (cli *httpAlertsClient) Subscribe(ctx context.Context, input *services.SubscribeInput) ([]*models.Subscription, error) {
	url := fmt.Sprintf("%s/v1/user/%s/subscribe", cli.baseUrl, input.UserID)
	sub, err := Post[models.Subscription](ctx, cli.httpClient, url, input, nil)
	return []*models.Subscription{&sub}, err
}

func (cli *httpAlertsClient) Unsubscribe(ctx context.Context, input *services.UnsubscribeInput) ([]*models.Subscription, error) {
	url := fmt.Sprintf("%s/v1/user/%s/unsubscribe/%s", cli.baseUrl, input.UserID, input.SubscriptionID)
	sub, err := Post[models.Subscription](ctx, cli.httpClient, url, nil, nil)
	return []*models.Subscription{&sub}, err
}

func (cli *httpAlertsClient) HandleEvent(ctx context.Context, input *services.HandleEventInput) error {
	panic("This method is not intended to be called on the client side")
}

func (cli *httpAlertsClient) GetEvents(ctx context.Context, input *services.GetEventsInput) (string, error) {
	url := cli.baseUrl + "/v1/events"
	return IterGet[models.StoredEvent, *resources.GetItemsResponse[models.StoredEvent]](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpAlertsClient) GetEventByID(ctx context.Context, input *services.GetEventByIDInput) (*models.StoredEvent, error) {
	url := fmt.Sprintf("%s/v1/events/%s", cli.baseUrl, input.ID)
	ev, err := Get[models.StoredEvent](ctx, cli.httpClient, url, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &ev, nil
}

func (cli *httpAlertsClient) GetEventRetentionSettings(ctx context.Context) (*models.EventRetentionSettings, error) {
	settings, err := Get[models.EventRetentionSettings](ctx, cli.httpClient, cli.baseUrl+"/v1/config/event-retention", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &settings, nil
}

func (cli *httpAlertsClient) UpdateEventRetentionSettings(ctx context.Context, input *services.UpdateEventRetentionSettingsInput) (*models.EventRetentionSettings, error) {
	settings, err := Put[models.EventRetentionSettings](ctx, cli.httpClient, cli.baseUrl+"/v1/config/event-retention", input, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &settings, nil
}

func NewHttpAlertsClient(client *http.Client, url string) services.AlertsService {
	baseURL := url
	return &httpAlertsClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}
