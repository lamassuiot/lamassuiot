package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

type fakeRDSDBClusterDescriber struct {
	input  *rds.DescribeDBClustersInput
	output *rds.DescribeDBClustersOutput
	err    error
}

func (f *fakeRDSDBClusterDescriber) DescribeDBClusters(_ context.Context, input *rds.DescribeDBClustersInput, _ ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	f.input = input
	return f.output, f.err
}

type fakeDatabaseSecretGetter struct {
	input  *secretsmanager.GetSecretValueInput
	output *secretsmanager.GetSecretValueOutput
	err    error
}

func (f *fakeDatabaseSecretGetter) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.input = input
	return f.output, f.err
}

func TestBuildAuthzMigrationDBConfig(t *testing.T) {
	clusterAPI := &fakeRDSDBClusterDescriber{
		output: &rds.DescribeDBClustersOutput{
			DBClusters: []rdstypes.DBCluster{{
				Endpoint: aws.String("database.cluster.example.com"),
				Port:     aws.Int32(5432),
			}},
		},
	}
	secretAPI := &fakeDatabaseSecretGetter{
		output: &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(`{"username":"db-user","password":"db-password"}`),
		},
	}

	migrationDB, err := buildAuthzMigrationDBConfig(
		context.Background(),
		"arn:aws:rds:us-east-1:123456789012:cluster:example",
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:example",
		"pki",
		clusterAPI,
		secretAPI,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := *clusterAPI.input.DBClusterIdentifier; got != "arn:aws:rds:us-east-1:123456789012:cluster:example" {
		t.Fatalf("unexpected RDS cluster identifier: %s", got)
	}
	if got := *secretAPI.input.SecretId; got != "arn:aws:secretsmanager:us-east-1:123456789012:secret:example" {
		t.Fatalf("unexpected Secrets Manager identifier: %s", got)
	}
	if got := migrationDB.Config["hostname"]; got != "database.cluster.example.com" {
		t.Fatalf("unexpected migration host: %v", got)
	}
	if got := migrationDB.Config["port"]; got != 5432 {
		t.Fatalf("unexpected migration port: %v", got)
	}
	if got := migrationDB.Config["username"]; got != "db-user" {
		t.Fatalf("unexpected migration username: %v", got)
	}
	if got := migrationDB.Config["password"]; got != cconfig.Password("db-password") {
		t.Fatalf("unexpected migration password type or value")
	}
	if got := migrationDB.Config["database"]; got != "pki" {
		t.Fatalf("unexpected migration database: %v", got)
	}
	if got := migrationDB.Config["schema"]; got != "authz" {
		t.Fatalf("unexpected migration schema: %v", got)
	}
	if got := migrationDB.Config["sslmode"]; got != "require" {
		t.Fatalf("expected TLS to be required for the RDS migration connection, got %v", got)
	}
}

func TestBuildAuthzMigrationDBConfigPropagatesRDSLookupErrors(t *testing.T) {
	clusterAPI := &fakeRDSDBClusterDescriber{err: errors.New("access denied")}
	secretAPI := &fakeDatabaseSecretGetter{}

	_, err := buildAuthzMigrationDBConfig(
		context.Background(),
		"cluster-arn",
		"secret-arn",
		"pki",
		clusterAPI,
		secretAPI,
	)
	if err == nil || !strings.Contains(err.Error(), "describe RDS cluster") {
		t.Fatalf("expected RDS lookup error, got %v", err)
	}
}

func TestBuildAuthzMigrationDBConfigRejectsIncompleteSecret(t *testing.T) {
	clusterAPI := &fakeRDSDBClusterDescriber{
		output: &rds.DescribeDBClustersOutput{
			DBClusters: []rdstypes.DBCluster{{
				Endpoint: aws.String("database.cluster.example.com"),
				Port:     aws.Int32(5432),
			}},
		},
	}
	secretAPI := &fakeDatabaseSecretGetter{
		output: &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(`{"username":"db-user"}`),
		},
	}

	_, err := buildAuthzMigrationDBConfig(
		context.Background(),
		"cluster-arn",
		"secret-arn",
		"pki",
		clusterAPI,
		secretAPI,
	)
	if err == nil || !strings.Contains(err.Error(), "username and password") {
		t.Fatalf("expected incomplete credentials error, got %v", err)
	}
}
