package eventfilters

import (
	"encoding/json"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/kaptinlin/jsonschema"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func RegisterJSONSchemaFilter() {
	RegisterEventFilter(models.JSONSchema,
		func(c models.SubscriptionCondition, event cloudevents.Event) (bool, error) {
			return filterJSONSchema(event, c.Condition)
		})
}

func filterJSONSchema(event cloudevents.Event, schemaCondition string) (bool, error) {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile([]byte(schemaCondition))
	if err != nil {
		return false, err
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return false, err
	}

	var data map[string]interface{}
	err = json.Unmarshal(encoded, &data)
	if err != nil {
		return false, err
	}

	result := schema.Validate(data)
	return result.Valid, nil
}
