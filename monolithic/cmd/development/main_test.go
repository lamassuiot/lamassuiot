package main

import (
	"strings"
	"testing"
)

func TestValidatePostgresTransport(t *testing.T) {
	tests := []struct {
		name        string
		transport   string
		disableWFX  bool
		enableAuthz bool
		migration   bool
		wantError   string
	}{
		{
			name:      "direct transport allows authz",
			transport: "direct",
		},
		{
			name:      "Data API requires WFX disabled",
			transport: "rds_data_api",
			wantError: "-disable-wfx",
		},
		{
			name:        "Data API requires direct migration settings for authz",
			transport:   "rds_data_api",
			disableWFX:  true,
			enableAuthz: true,
			wantError:   "-authz-migration-host",
		},
		{
			name:        "Data API allows authz with direct migration settings",
			transport:   "rds_data_api",
			disableWFX:  true,
			enableAuthz: true,
			migration:   true,
		},
		{
			name:       "Data API is allowed without incompatible services",
			transport:  "rds_data_api",
			disableWFX: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePostgresTransport(
				test.transport,
				"resource-arn",
				"secret-arn",
				"database",
				"region",
				test.disableWFX,
				test.enableAuthz,
				migrationValue(test.migration, "postgres.example.com"),
				migrationValue(test.migration, "migrator"),
				migrationValue(test.migration, "pki"),
				migrationValue(test.migration, "secret"),
			)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected validation error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("expected error containing %q, got %v", test.wantError, err)
			}
		})
	}
}

func migrationValue(enabled bool, value string) string {
	if !enabled {
		return ""
	}
	return value
}
