package eventfilters

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/robertkrimen/otto"
)

func RegisterJavascriptFilter() {
	RegisterEventFilter(models.Javascript,
		func(c models.SubscriptionCondition, event cloudevents.Event) (bool, error) {
			return javascriptFilter(event, c.Condition)
		})
}

const javascriptFilterTimeout = 100 * time.Millisecond

var errJavascriptFilterTimeout = errors.New("javascript filter execution timed out")

// javascriptFilter evaluates a function(event) bool with a bounded lifetime.
func javascriptFilter(event cloudevents.Event, script string) (bool, error) {
	vm := otto.New()
	vm.Interrupt = make(chan func(), 1)
	type outcome struct {
		matched bool
		err     error
	}
	finished := make(chan outcome, 1)
	go func() {
		result := outcome{err: errJavascriptFilterTimeout}
		defer func() { finished <- result }()
		result.matched, result.err = evaluateJavascriptFilter(vm, event, script)
	}()
	// Goexit terminates the VM's worker and runs its cleanup. Unlike a panic,
	// it cannot be caught by JavaScript try/catch or finally blocks in Otto.
	timer := time.AfterFunc(javascriptFilterTimeout, func() {
		vm.Interrupt <- runtime.Goexit
	})
	defer timer.Stop()
	result := <-finished
	return result.matched, result.err
}

func evaluateJavascriptFilter(vm *otto.Otto, event cloudevents.Event, script string) (bool, error) {
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
