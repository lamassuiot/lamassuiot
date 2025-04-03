package eventfilters

import (
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
)

func TestFilterJSONSchema(t *testing.T) {
	tests := []struct {
		name           string
		eventData      interface{}
		schema         string
		expectedResult bool
		wantErr        bool
	}{
		{
			name: "ValidSchemaAndMatchingData",
			eventData: map[string]interface{}{
				"name": "John",
				"age":  30,
			},
			schema: `{
					"type": "object",
					"properties": {
						"data": {
						"type": "object",
						"properties": {
							"name": {
							"type": "string"
							},
							"age": {
							"type": "integer"
							}
						},
						"required": [
							"name",
							"age"
						]
						}
					}
					}`,
			expectedResult: true,
			wantErr:        false,
		},
		{
			name: "ValidSchemaAndNonMatchingData",
			eventData: map[string]interface{}{
				"name": "John",
			},
			schema: `{
					"type": "object",
					"properties": {
						"data": {
						"type": "object",
						"properties": {
							"name": {
							"type": "string"
							},
							"age": {
							"type": "integer"
							}
						},
						"required": [
							"name",
							"age"
						]
						}
					}
					}`,
			expectedResult: false,
			wantErr:        false,
		},
		{
			name: "InvalidSchema",
			eventData: map[string]interface{}{
				"name": "John",
				"age":  30,
			},
			schema:         `{"type": "object", "properties": {"name": {"type": "string"}, "age": {"type": "integer"}`,
			expectedResult: false,
			wantErr:        true,
		},
		{
			name: "EmptySchema",
			eventData: map[string]interface{}{
				"name": "John",
				"age":  30,
			},
			schema:         ``,
			expectedResult: false,
			wantErr:        true,
		},
		{
			name: "ValidSchemaWithAdditionalProperties",
			eventData: map[string]interface{}{
				"name":    "John",
				"age":     30,
				"address": "123 Street",
			},
			schema: `{
					"type": "object",
					"properties": {
						"data": {
						"type": "object",
						"properties": {
							"name": {
							"type": "string"
							},
							"age": {
							"type": "integer"
							}
						},
						"required": [
							"name",
							"age"
						],
						"additionalProperties": false
						}
					}
					}`,
			expectedResult: false,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := cloudevents.NewEvent()
			err := event.SetData(cloudevents.ApplicationJSON, tt.eventData)
			assert.NoError(t, err)

			result, err := filterJSONSchema(event, tt.schema)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
