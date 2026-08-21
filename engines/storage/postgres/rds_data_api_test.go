package postgres

import (
	"context"
	"os"
	"testing"

	lconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"github.com/sirupsen/logrus"
)

func TestRDSDataAPIConnection(t *testing.T) {
	cfg := lconfig.PostgresPSEConfig{
		Transport:      lconfig.RDSDataAPI,
		RDSResourceARN: "arn:aws:rds:eu-west-1:030101238523:cluster:database-1",
		RDSSecretARN:   os.Getenv("LAMASSU_RDS_SECRET_ARN"),
		AWSRegion:      os.Getenv("AWS_REGION"),
	}
	if cfg.RDSResourceARN == "" || cfg.RDSSecretARN == "" || cfg.AWSRegion == "" {
		t.Skip("set LAMASSU_RDS_RESOURCE_ARN, LAMASSU_RDS_SECRET_ARN, and AWS_REGION to run the RDS Data API smoke test")
	}

	db, err := CreatePostgresDBConnection(logrus.NewEntry(logrus.New()), cfg, CA_SCHEMA)
	if err != nil {
		t.Fatalf("CreatePostgresDBConnection() error: %v", err)
	}

	var value int
	if err := db.WithContext(context.Background()).Raw("SELECT 1").Scan(&value).Error; err != nil {
		t.Fatalf("execute Data API query: %v", err)
	}
	if value != 1 {
		t.Fatalf("SELECT 1 returned %d, want 1", value)
	}
}
