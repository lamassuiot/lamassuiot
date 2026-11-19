package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBigIntUnmarshalJSON(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{`0`, "0"}, {`123456789012345678901234567890`, "123456789012345678901234567890"}, {`"42"`, "42"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			var value BigInt
			require.NoError(t, json.Unmarshal([]byte(tc.input), &value))
			require.Equal(t, tc.want, value.String())
		})
	}
	t.Run("invalid numeric string", func(t *testing.T) {
		var value BigInt
		require.Error(t, json.Unmarshal([]byte(`"not-a-number"`), &value))
	})
}
