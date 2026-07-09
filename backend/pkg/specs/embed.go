package specs

import _ "embed"

//go:embed ca-openapi.yaml
var CA []byte

//go:embed kms-openapi.yaml
var KMS []byte

//go:embed va-openapi.yaml
var VA []byte

//go:embed dms-manager-openapi.yaml
var DMSManager []byte

//go:embed device-manager-openapi.yaml
var DeviceManager []byte

//go:embed alerts-openapi.yaml
var Alerts []byte
