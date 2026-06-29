package eventfilters

import (
	"encoding/json"
	"fmt"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/robertkrimen/otto"
)

func RegisterJavascriptFilter() {
	RegisterEventFilter(models.Javascript,
		func(c models.SubscriptionCondition, event cloudevents.Event) (bool, error) {
			return javascriptFilter(event, c.Condition)
		})
}

// JavascriptFilter evaluates the given script with the data as input
// the source code of the script is provided with the following signature:
// func(event: string) bool
// The function should return true if the data matches the condition
// and false otherwise
func javascriptFilter(event cloudevents.Event, script string) (bool, error) {
	vm := otto.New()
	encoded, err := json.Marshal(event)
	if err != nil {
		return false, err
	}

	var parsed interface{}
	if err := json.Unmarshal(encoded, &parsed); err != nil {
		return false, err
	}
	vm.Set("event", parsed)

	// Register script as a function
	jsfunc, err := vm.Object("(" + script + ")")
	if err != nil {
		return false, err
	}
	if jsfunc.Value().IsFunction() {
		vm.Set("filter", jsfunc)
		script = "filter(event)"
		result, err := vm.Run(script)
		if err != nil {
			return false, err
		}
		if result.IsBoolean() {
			return result.ToBoolean()
		} else {
			return false, fmt.Errorf("script returned non-boolean value")
		}

	} else {
		return false, err
	}
}
