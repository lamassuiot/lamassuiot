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

func NewHttpAlertsClient(client *http.Client, url string) services.AlertsService {
	baseURL := url
	return &httpAlertsClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}
