package api

import (
	"strings"
	"testing"
)

func TestNormalizeEntityType(t *testing.T) {
	tests := []struct {
		name        string
		schemaName  string
		entityType  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid separated fields",
			schemaName: "public",
			entityType: "device",
		},
		{
			name:        "reject qualified entityType",
			schemaName:  "public",
			entityType:  "public.device",
			wantErr:     true,
			errContains: "unqualified",
		},
		{
			name:        "reject missing schemaName",
			schemaName:  " ",
			entityType:  "device",
			wantErr:     true,
			errContains: "schemaName is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEntityIdentifier(tc.schemaName, tc.entityType)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}
