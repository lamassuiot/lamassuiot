package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

type rdsDBClusterDescriber interface {
	DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
}

type databaseSecretGetter interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

func resolveAuthzMigrationDBConfig(ctx context.Context, resourceARN, secretARN, database, region string) (cconfig.PluggableStorageEngine, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("load AWS configuration for Authz migration settings: %w", err)
	}

	return buildAuthzMigrationDBConfig(
		ctx,
		resourceARN,
		secretARN,
		database,
		rds.NewFromConfig(awsCfg),
		secretsmanager.NewFromConfig(awsCfg),
	)
}

func buildAuthzMigrationDBConfig(
	ctx context.Context,
	resourceARN, secretARN, database string,
	clusterAPI rdsDBClusterDescriber,
	secretAPI databaseSecretGetter,
) (cconfig.PluggableStorageEngine, error) {
	if strings.TrimSpace(resourceARN) == "" {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("RDS cluster resource ARN is required to resolve Authz migration settings")
	}
	if strings.TrimSpace(secretARN) == "" {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("Secrets Manager secret ARN is required to resolve Authz migration settings")
	}
	if strings.TrimSpace(database) == "" {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("database name is required to resolve Authz migration settings")
	}

	clusterOutput, err := clusterAPI.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(resourceARN),
	})
	if err != nil {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("describe RDS cluster for Authz migrations: %w", err)
	}
	if clusterOutput == nil || len(clusterOutput.DBClusters) == 0 {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("RDS cluster was not found for Authz migrations")
	}
	cluster := clusterOutput.DBClusters[0]
	if cluster.Endpoint == nil || strings.TrimSpace(*cluster.Endpoint) == "" {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("RDS cluster response has no endpoint for Authz migrations")
	}
	if cluster.Port == nil || *cluster.Port < 1 {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("RDS cluster response has no valid port for Authz migrations")
	}

	secretOutput, err := secretAPI.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretARN),
	})
	if err != nil {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("retrieve PostgreSQL credentials for Authz migrations: %w", err)
	}
	if secretOutput == nil {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("Secrets Manager returned no PostgreSQL credentials for Authz migrations")
	}

	var secretJSON []byte
	switch {
	case secretOutput.SecretString != nil:
		secretJSON = []byte(*secretOutput.SecretString)
	case len(secretOutput.SecretBinary) > 0:
		secretJSON = secretOutput.SecretBinary
	default:
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("Secrets Manager secret has no value for Authz migrations")
	}

	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(secretJSON, &credentials); err != nil {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("parse PostgreSQL credentials for Authz migrations: %w", err)
	}
	if strings.TrimSpace(credentials.Username) == "" || strings.TrimSpace(credentials.Password) == "" {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("Secrets Manager secret must contain non-empty username and password fields for Authz migrations")
	}

	return cconfig.PluggableStorageEngine{
		Provider: cconfig.Postgres,
		Config: map[string]any{
			"hostname": *cluster.Endpoint,
			"port":     int(*cluster.Port),
			"username": credentials.Username,
			"password": cconfig.Password(credentials.Password),
			"database": database,
			"schema":   "authz",
			"sslmode":  "require",
		},
	}, nil
}
