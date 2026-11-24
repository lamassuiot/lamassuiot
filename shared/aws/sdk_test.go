package aws

import (
	"context"
	"testing"
)

func TestGetAwsSdkConfigUsesConfiguredEnvironmentCredentials(t *testing.T) {
	t.Setenv("LAMASSU_TEST_ACCESS_KEY_ID", "access-key")
	t.Setenv("LAMASSU_TEST_SECRET_ACCESS_KEY", "secret-key")

	config, err := GetAwsSdkConfig(AWSSDKConfig{
		AWSAuthenticationMethod: Default,
		AccessKeyIDEnv:          "LAMASSU_TEST_ACCESS_KEY_ID",
		SecretAccessKeyEnv:      "LAMASSU_TEST_SECRET_ACCESS_KEY",
		Region:                  "eu-west-1",
	})
	if err != nil {
		t.Fatalf("GetAwsSdkConfig returned an error: %v", err)
	}

	credentials, err := config.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("could not retrieve configured credentials: %v", err)
	}
	if credentials.AccessKeyID != "access-key" || credentials.SecretAccessKey != "secret-key" {
		t.Fatalf("unexpected credentials: %s/%s", credentials.AccessKeyID, credentials.SecretAccessKey)
	}
}

func TestGetAwsSdkConfigRejectsMissingConfiguredEnvironmentCredential(t *testing.T) {
	_, err := GetAwsSdkConfig(AWSSDKConfig{
		AWSAuthenticationMethod: Default,
		AccessKeyIDEnv:          "LAMASSU_TEST_MISSING_ACCESS_KEY_ID",
		Region:                  "eu-west-1",
	})
	if err == nil {
		t.Fatal("GetAwsSdkConfig succeeded with a missing configured credential variable")
	}
}
