package eventfilters

import (
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJavascriptFilter(t *testing.T) {
	tests := []struct {
		name     string
		event    cloudevents.Event
		script   string
		expected bool
		wantErr  bool
	}{
		{
			name: "valid script returns true",
			event: func() cloudevents.Event {
				e := cloudevents.NewEvent()
				e.SetData(cloudevents.ApplicationJSON, map[string]interface{}{"key": "value"})
				return e
			}(),
			script:   "function(event) { return event.data.key === 'value'; }",
			expected: true,
			wantErr:  false,
		},
		{
			name: "valid script returns false",
			event: func() cloudevents.Event {
				e := cloudevents.NewEvent()
				e.SetData(cloudevents.ApplicationJSON, map[string]interface{}{"key": "other"})
				return e
			}(),
			script:   "function(event) { return event.data.key === 'value'; }",
			expected: false,
			wantErr:  false,
		},
		{
			name: "invalid script",
			event: func() cloudevents.Event {
				e := cloudevents.NewEvent()
				e.SetData(cloudevents.ApplicationJSON, map[string]interface{}{"key": "value"})
				return e
			}(),
			script:  "function(event) { return event.data.key === 'value' ",
			wantErr: true,
		},
		{
			name: "script returns non-boolean value",
			event: func() cloudevents.Event {
				e := cloudevents.NewEvent()
				e.SetData(cloudevents.ApplicationJSON, map[string]interface{}{"key": "value"})
				return e
			}(),
			script:   "function(event) { return event.data.key }",
			expected: false,
			wantErr:  true,
		},
		{
			name: "script execution error",
			event: func() cloudevents.Event {
				e := cloudevents.NewEvent()
				e.SetData(cloudevents.ApplicationJSON, map[string]interface{}{"key": "value"})
				return e
			}(),
			script:  "function(event) { throw new Error('error'); }",
			wantErr: true,
		},
		{
			name: "script execution multiple functions error",
			event: func() cloudevents.Event {
				e := cloudevents.NewEvent()
				e.SetData(cloudevents.ApplicationJSON, map[string]interface{}{"key": "value"})
				return e
			}(),
			script: `
			function(event) { return true; }
			function(event) { return true; }
		`,
			wantErr: true,
		},
		{
			name: "script execution not a function",
			event: func() cloudevents.Event {
				e := cloudevents.NewEvent()
				e.SetData(cloudevents.ApplicationJSON, map[string]interface{}{"key": "value"})
				return e
			}(),
			script:   "{'a': 1}",
			expected: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := javascriptFilter(tt.event, tt.script)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
