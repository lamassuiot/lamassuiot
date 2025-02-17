package eventfilters

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/spyzhov/ajson"
)

func RegisterJSONPathFilter() {
	RegisterEventFilter(models.JSONPath,
		func(c models.SubscriptionCondition, event cloudevents.Event) (bool, error) {
			return JsonPathExists(event.Data(), c.Condition)
		})
}

func JsonPathExists(data []byte, path string) (bool, error) {
	ajsonData, err := ajson.JSONPath(data, path)
	if err != nil {
		return false, err
	}

	return len(ajsonData) > 0, nil
}
