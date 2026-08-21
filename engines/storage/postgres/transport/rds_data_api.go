package transport

import (
	"context"
	"database/sql"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rdsdata"
	rds "github.com/krotscheck/go-rds-driver"
	postgresconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

func openRDSDataAPI(ctx context.Context, cfg postgresconfig.PostgresPSEConfig, schemaName string, logger gormlogger.Interface) (*gorm.DB, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration for RDS Data API: %w", err)
	}

	rdsConfig := rds.NewConfig(cfg.RDSResourceARN, cfg.RDSSecretARN, "pki", cfg.AWSRegion)
	rdsConfig.ParseTime = true
	sqlDB := sql.OpenDB(rds.NewConnector(rds.NewDriver(), rdsdata.NewFromConfig(awsCfg), rdsConfig))

	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{
		Logger:         logger,
		NamingStrategy: schema.NamingStrategy{TablePrefix: schemaName + "."},
	})
	if err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("open RDS Data API GORM connection: %w", err)
	}

	return db.Set(schemaKey, schemaName), nil
}
