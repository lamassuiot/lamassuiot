package migrations

import (
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/ca"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/dmsmanager"
)

// the order of the migrations is NOT IMPORTANT. It is only necessary to register them all
func RegisterGoMigrations(dbname string) {
	switch dbname {
	case "ca":
		ca.Register20250123125500CaAwsMetadata()
		ca.Register20250226114600CaAddKids()
		ca.Register20250908074250AddProfileId()
		ca.Register20250915090500UpdateSkiAki()
	case "dmsmanager":
		dmsmanager.Register20241230124809ServerkeygenRevokereenroll()
		dmsmanager.Register20250612100530ESTVerifyCSRSignature()
	}
}
