package migrations

import (
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/ca"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/devicemanager"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/dmsmanager"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/kms"
)

// the order of the migrations is NOT IMPORTANT. It is only necessary to register them all
func RegisterGoMigrations(dbname string) {
	switch dbname {
	case "ca":
		ca.Register20250123125500CaAwsMetadata()
		ca.Register20250226114600CaAddKids()
		ca.Register20250908074250AddProfileId()
		ca.Register20250915090500UpdateSkiAki()
		ca.Register20260331120000AddCertificateExtensions()
		ca.Register20261020120000BackfillCertificateIssuer()
	case "devicemanager":
		devicemanager.Register20250925120000RemoveSerialHyphens()
	case "dmsmanager":
		dmsmanager.Register20241230124809ServerkeygenRevokereenroll()
		dmsmanager.Register20250612100530ESTVerifyCSRSignature()
		dmsmanager.Register20260604110000ReenrollAuthSettings()
		dmsmanager.Register20261021120000WebhookHTTPClientConfig()
		dmsmanager.Register20261022120000ReenrollValidationCAs()
	case "kms":
		kms.Register20261020100000ReconcileKeyBindings()
	}
}
