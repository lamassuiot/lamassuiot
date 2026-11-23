package docs_test

import (
	"bytes"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/docs"
	"github.com/lamassuiot/lamassuiot/v4/docs/specs"
)

func TestLegacySpecifications(t *testing.T) {
	for name, pair := range map[string][2][]byte{
		"CA":                    {docs.CA, specs.CA},
		"KMS":                   {docs.KMS, specs.KMS},
		"VA":                    {docs.VA, specs.VA},
		"DMSManager":            {docs.DMSManager, specs.DMSManager},
		"DeviceManager":         {docs.DeviceManager, specs.DeviceManager},
		"Alerts":                {docs.Alerts, specs.Alerts},
		"EnrollReenrollWebhook": {docs.EnrollReenrollWebhook, specs.EnrollReenrollWebhook},
		"Authz":                 {docs.Authz, specs.Authz},
	} {
		if len(pair[0]) == 0 || !bytes.Equal(pair[0], pair[1]) {
			t.Errorf("%s: legacy and current specifications differ or are empty", name)
		}
	}
}
