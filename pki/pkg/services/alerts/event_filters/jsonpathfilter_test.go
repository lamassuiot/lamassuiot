package eventfilters

import (
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
)

func TestJsonPathExists(t *testing.T) {
	tests := []struct {
		name     string
		data     interface{}
		path     string
		expected bool
		wantErr  bool
	}{
		{
			name: "ValidPathExists",
			data: map[string]interface{}{
				"name": "John",
				"age":  30,
			},
			path:     "$.data.name",
			expected: true,
			wantErr:  false,
		},
		{
			name: "ValidPathDoesNotExist",
			data: map[string]interface{}{
				"name": "John",
				"age":  30,
			},
			path:     "$.data.address",
			expected: false,
			wantErr:  false,
		},
		{
			name: "InvalidPath",
			data: map[string]interface{}{
				"name": "John",
				"age":  30,
			},
			path:     "$.[.name",
			expected: false,
			wantErr:  true,
		},
		{
			name: "NestedPathExists",
			data: map[string]interface{}{
				"person": map[string]interface{}{
					"name": "John",
					"age":  30,
				},
			},
			path:     "$.data.person.name",
			expected: true,
			wantErr:  false,
		},
		{
			name: "NestedPathDoesNotExist",
			data: map[string]interface{}{
				"person": map[string]interface{}{
					"name": "John",
					"age":  30,
				},
			},
			path:     "$.data.person.address",
			expected: false,
			wantErr:  false,
		},
		{
			name: "NestedPathWithExpressionExists",
			data: map[string]interface{}{
				"person": map[string]interface{}{
					"name": "John",
					"age":  30,
				},
			},
			path:     "$.data[?(@.name == 'John')]",
			expected: true,
			wantErr:  false,
		},
		{
			name: "NestedPathWithExpressionNotExists",
			data: map[string]interface{}{
				"person": map[string]interface{}{
					"name": "John",
					"age":  30,
				},
			},
			path:     `$.data[?(@.name=="James")]`,
			expected: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := cloudevents.NewEvent()
			e.SetData(cloudevents.ApplicationJSON, tt.data)
			result, err := jsonPathFilter(e, tt.path)
			// b, _ := json.Marshal(tt.data)
			// result, err := JsonPathExists(b, tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}
