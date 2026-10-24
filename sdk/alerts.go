package sdk

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
)

type httpAlertsClient struct {
	restClient
}

func (cli *httpAlertsClient) GetLatestEventsPerEventType(ctx context.Context, input *services.GetLatestEventsPerEventTypeInput) (string, error) {
	path := "/v1/events/latest"
	if input == nil {
		input = &services.GetLatestEventsPerEventTypeInput{}
	}
	if input.ApplyFunc == nil {
		input.ApplyFunc = func(models.AlertLatestEvent) {}
	}

	return cli.iterGet[models.AlertLatestEvent, *resources.GetAlertsResponse](
		ctx,
		path,
		input.ExhaustiveRun,
		input.QueryParameters,
		input.ApplyFunc,
		map[int][]error{},
	)
}

func (cli *httpAlertsClient) GetUserSubscriptions(ctx context.Context, input *services.GetUserSubscriptionsInput) ([]*models.Subscription, error) {
	path := fmt.Sprintf("/v1/user/%s/subscriptions", input.UserID)
	results := make([]*models.Subscription, 0)
	_, err := cli.iterGet[models.Subscription, *resources.GetItemsResponse[models.Subscription]](ctx, path, true, nil,
		func(ale models.Subscription) {
			results = append(results, &ale)
		}, map[int][]error{})
	return results, err
}

func (cli *httpAlertsClient) Subscribe(ctx context.Context, input *services.SubscribeInput) ([]*models.Subscription, error) {
	path := fmt.Sprintf("/v1/user/%s/subscribe", input.UserID)
	sub, err := cli.post[models.Subscription](ctx, path, input, nil)
	return []*models.Subscription{&sub}, err
}

func (cli *httpAlertsClient) Unsubscribe(ctx context.Context, input *services.UnsubscribeInput) ([]*models.Subscription, error) {
	path := fmt.Sprintf("/v1/user/%s/unsubscribe/%s", input.UserID, input.SubscriptionID)
	sub, err := cli.post[models.Subscription](ctx, path, nil, nil)
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
