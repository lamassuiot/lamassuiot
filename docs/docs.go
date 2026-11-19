// Package docs preserves the original import path for the OpenAPI specifications.
// New code should import github.com/lamassuiot/lamassuiot/v4/docs/specs.
package docs

import "github.com/lamassuiot/lamassuiot/v4/docs/specs"

var (
	CA                    = specs.CA
	KMS                   = specs.KMS
	VA                    = specs.VA
	DMSManager            = specs.DMSManager
	DeviceManager         = specs.DeviceManager
	Alerts                = specs.Alerts
	EnrollReenrollWebhook = specs.EnrollReenrollWebhook
	Authz                 = specs.Authz
)
