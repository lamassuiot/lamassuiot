package config

import (
	"strings"
	"testing"
)

func TestPostgresPSEConfigUsesRDSDataAPI(t *testing.T) {
	tests := []struct {
		name      string
		transport ConnectionTransport
		want      bool
	}{
		{name: "defaults to direct connection", want: false},
		{name: "uses Data API when configured", transport: RDSDataAPI, want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := PostgresPSEConfig{Transport: test.transport}
			if got := cfg.UsesRDSDataAPI(); got != test.want {
				t.Fatalf("UsesRDSDataAPI() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestPostgresPSEConfigValidate(t *testing.T) {
	tests := []struct {
		name string
		cfg  PostgresPSEConfig
		want string
	}{
		{name: "direct connection does not need Data API settings"},
		{
			name: "requires resource ARN",
			cfg:  PostgresPSEConfig{Transport: RDSDataAPI},
			want: "rds_resource_arn",
		},
		{
			name: "requires secret ARN",
			cfg: PostgresPSEConfig{
				Transport:      RDSDataAPI,
				RDSResourceARN: "cluster-arn",
			},
			want: "rds_secret_arn",
		},
		{
			name: "requires AWS region",
			cfg: PostgresPSEConfig{
				Transport:      RDSDataAPI,
				RDSResourceARN: "cluster-arn",
				RDSSecretARN:   "secret-arn",
			},
			want: "aws_region",
		},
		{
			name: "accepts complete Data API configuration",
			cfg: PostgresPSEConfig{
				Transport:      RDSDataAPI,
				RDSResourceARN: "cluster-arn",
				RDSSecretARN:   "secret-arn",
				AWSRegion:      "eu-west-1",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.cfg.Validate()
			if test.want == "" && err != nil {
				t.Fatalf("Validate() returned unexpected error: %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("Validate() error = %v, want message containing %q", err, test.want)
			}
		})
	}
}
