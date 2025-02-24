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

// EvalConditions evaluates a list of subscription conditions against a given CloudEvent.
// It returns true if any of the conditions are met, otherwise false.
// If an error occurs during the evaluation of any condition, it returns false and the error.
//
// Parameters:
//   - conditions: A slice of SubscriptionCondition objects to be evaluated.
//   - event: The CloudEvent to be evaluated against the conditions.
//
// Returns:
//   - bool: True if any condition is met, otherwise false.
//   - error: An error if any occurs during the evaluation of the conditions.
func EvalConditions(conditions []models.SubscriptionCondition, event cloudevents.Event) (bool, error) {
	if len(conditions) == 0 {
		return true, nil
	}

	for _, c := range conditions {
		ok, err := EvalFilter(c, event)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func init() {
	RegisterJSONPathFilter()
	RegisterJSONSchemaFilter()
}
