package config_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	awsplatform_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/aws-platform"
)

func TestGetAwsSdkConfig(t *testing.T) {
	containerCleanup, conf, err := awsplatform_test.RunAWSEmulationLocalStackDocker()
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	t.Cleanup(func() { _ = containerCleanup() })

	conf.AWSAuthenticationMethod = config.Static
	// Test Static authentication method
	awsCfg, err := config.GetAwsSdkConfig(*conf)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if awsCfg.Region != conf.Region {
		t.Errorf("unexpected region, got: %s, want: %s", awsCfg.Region, conf.Region)
	}
	if awsCfg.Credentials == nil {
		t.Errorf("unexpected credentials, got: nil")
	}

	endpoint, err := awsCfg.EndpointResolverWithOptions.ResolveEndpoint("s3", conf.Region)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if (endpoint.URL != conf.EndpointURL) || (endpoint.SigningRegion != conf.Region) {
		t.Errorf("unexpected endpoint, got: %s, want: %s", endpoint.URL, conf.EndpointURL)
	}

	// reset endpoint
	conf.EndpointURL = ""
	awsCfg, err = config.GetAwsSdkConfig(*conf)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	_, err = awsCfg.EndpointResolverWithOptions.ResolveEndpoint("s3", conf.Region)
	if _, ok := err.(*aws.EndpointNotFoundError); !ok {
		t.Errorf("unexpected error: %s", err)
	}

	// Test AssumeRole authentication method
	conf.AWSAuthenticationMethod = config.AssumeRole
	awsCfg, err = config.GetAwsSdkConfig(*conf)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if awsCfg.Region != conf.Region {
		t.Errorf("unexpected region, got: %s, want: %s", awsCfg.Region, conf.Region)
	}

	if awsCfg.Credentials == nil {
		t.Errorf("unexpected credentials, got: nil")
	}
}
