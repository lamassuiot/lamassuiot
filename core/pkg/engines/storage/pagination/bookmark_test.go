package pagination

import (
	"encoding/base64"
	"testing"
)

func TestDecodeRejectsMalformedFilter(t *testing.T) {
	for _, raw := range []string{"off:0;lim:10;filter:bad;", "off:0;lim:10;filter:bmFtZQ==-1-!;"} {
		bookmark := base64.RawURLEncoding.EncodeToString([]byte(raw))
		if _, err := Decode(bookmark); err == nil {
			t.Fatalf("accepted malformed filter %q", raw)
		}
	}
}
