package sdk

import (
	"context"
	"net/http"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
)

func TestAddTenantContextHeader(t *testing.T) {
	tests := []struct {
		name       string
		ctx        context.Context
		expectedID string
		wantPath   string
		wantErr    bool
	}{
		{
			name: "validated tenant context",
			ctx: core.WithTenantContext(context.Background(), core.TenantContext{
				OrganizationID: "organization",
				TenantID:       "tenant-a",
				ActorID:        "actor",
				ActorType:      "mtls",
				CorrelationID:  "correlation",
				Source:         "test",
				TenantStatus:   core.TenantActive,
				Validated:      true,
			}),
			expectedID: "tenant-a",
			wantPath:   "/api/v2/tenants/tenant-a/cas/ca-a",
		},
		{
			name:     "missing tenant context",
			ctx:      context.Background(),
			wantPath: "/v1/cas/ca-a",
		},
		{
			name: "invalid tenant context",
			ctx: core.WithTenantContext(context.Background(), core.TenantContext{
				TenantID:  "tenant-a",
				Validated: true,
			}),
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "http://localhost/v1/cas/ca-a", nil)
			if err != nil {
				t.Fatal(err)
			}

			err = addTenantContextHeader(test.ctx, request)
			if (err != nil) != test.wantErr {
				t.Fatalf("expected error=%t, got %v", test.wantErr, err)
			}
			if err != nil {
				return
			}

			if got := request.Header.Get(tenantIDHeader); got != test.expectedID {
				t.Fatalf("expected tenant header %q, got %q", test.expectedID, got)
			}
			if got := request.URL.Path; got != test.wantPath {
				t.Fatalf("expected request path %q, got %q", test.wantPath, got)
			}
		})
	}
}

func TestKMSClientEndpointScopesOnlyValidatedTenantContexts(t *testing.T) {
	client := &httpKMSClient{baseUrl: "http://kms.test"}
	validContext := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "organization",
		TenantID:       "tenant-a",
		ActorID:        "actor",
		ActorType:      "service",
		CorrelationID:  "correlation",
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
	invalidContext := core.WithTenantContext(context.Background(), core.TenantContext{
		TenantID:  "tenant-a",
		Validated: true,
	})

	for _, test := range []struct {
		name    string
		ctx     context.Context
		wantURL string
		wantErr bool
	}{
		{name: "validated context selects tenant route", ctx: validContext, wantURL: "http://kms.test/api/v2/tenants/tenant-a/keys"},
		{name: "missing context retains legacy default route", ctx: context.Background(), wantURL: "http://kms.test/v1/keys"},
		{name: "invalid context is rejected", ctx: invalidContext, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := client.endpoint(test.ctx, "/keys")
			if (err != nil) != test.wantErr {
				t.Fatalf("expected error=%v, got %v", test.wantErr, err)
			}
			if err == nil && got != test.wantURL {
				t.Fatalf("expected endpoint %q, got %q", test.wantURL, got)
			}
		})
	}
}
