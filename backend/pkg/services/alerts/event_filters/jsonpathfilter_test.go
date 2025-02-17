package eventfilters

import (
	"encoding/json"
	"testing"

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
			path:     "$.name",
			expected: true,
			wantErr:  false,
		},
		{
			name: "ValidPathDoesNotExist",
			data: map[string]interface{}{
				"name": "John",
				"age":  30,
			},
			path:     "$.address",
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
			path:     "$.person.name",
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
			path:     "$.person.address",
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
			path:     "$.[?(@.name == 'John')]",
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
			path:     `$.[?(@.name=="James")]`,
			expected: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			b, _ := json.Marshal(tt.data)
			result, err := JsonPathExists(b, tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}
