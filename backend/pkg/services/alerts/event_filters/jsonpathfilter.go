package eventfilters

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func RegisterJSONPathFilter() {
	RegisterEventFilter(models.JSONPath,
		func(c models.SubscriptionCondition, event cloudevents.Event) (bool, error) {
			return helpers.JsonPathExists(event.Data(), c.Condition)
		})
}
