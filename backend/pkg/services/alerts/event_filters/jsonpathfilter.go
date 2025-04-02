package eventfilters

import (
	"encoding/json"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/spyzhov/ajson"
)

func RegisterJSONPathFilter() {
	RegisterEventFilter(models.JSONPath,
		func(c models.SubscriptionCondition, event cloudevents.Event) (bool, error) {
			return jsonPathFilter(event, c.Condition)
		})
}

func jsonPathFilter(event cloudevents.Event, path string) (bool, error) {
	encoded, err := json.Marshal(event)
	if err != nil {
		return false, err
	}
	return JsonPathExists(encoded, path)
}

func JsonPathExists(data []byte, path string) (bool, error) {
	ajsonData, err := ajson.JSONPath(data, path)
	if err != nil {
		return false, err
	}

	return len(ajsonData) > 0, nil
}
