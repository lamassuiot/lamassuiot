package eventfilters

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

var eventFilters = make(map[models.ConditionType]func(c models.SubscriptionCondition, event cloudevents.Event) (bool, error))

func RegisterEventFilter(name models.ConditionType, filter func(c models.SubscriptionCondition, event cloudevents.Event) (bool, error)) {
	eventFilters[name] = filter
}

func EvalFilter(s models.SubscriptionCondition, event cloudevents.Event) (bool, error) {
	filter, ok := eventFilters[s.Type]
	if !ok {
		return false, nil
	}
	return filter(s, event)
}

func init() {
	RegisterJSONPathFilter()
	RegisterJSONSchemaFilter()
}
