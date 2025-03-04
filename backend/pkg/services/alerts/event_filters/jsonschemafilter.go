package eventfilters

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/kaptinlin/jsonschema"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func RegisterJSONSchemaFilter() {
	RegisterEventFilter(models.JSONSchema,
		func(c models.SubscriptionCondition, event cloudevents.Event) (bool, error) {

			compiler := jsonschema.NewCompiler()
			schema, err := compiler.Compile([]byte(c.Condition))
			if err != nil {
				return false, err
			}
			data := make(map[string]interface{})
			event.DataAs(&data)
			result := schema.Validate(data)
			return result.Valid, nil
		})
}
