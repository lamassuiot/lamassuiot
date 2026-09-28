package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestTenantScopedHTTPConsumersUseV2Routes(t *testing.T) {
	tenantContext := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "organization-a",
		TenantID:       "tenant-a",
		ActorID:        "actor-a",
		ActorType:      "HUMAN",
		CorrelationID:  "tenant-url-test",
		Source:         "test",
		TenantStatus:   models.TenantActive,
		Validated:      true,
	})

	tests := []struct {
		name string
		path string
		call func(context.Context, *http.Client, string) error
	}{
		{
			name: "CA get",
			path: "/api/v2/tenants/tenant-a/cas/ca-a",
			call: func(ctx context.Context, client *http.Client, baseURL string) error {
				_, err := NewHttpCAClient(client, baseURL).GetCAByID(ctx, services.GetCAByIDInput{CAID: "ca-a"})
				return err
			},
		},
		{
			name: "CA manual stats request",
			path: "/api/v2/tenants/tenant-a/stats",
			call: func(ctx context.Context, client *http.Client, baseURL string) error {
				_, err := NewHttpCAClient(client, baseURL).GetStats(ctx, services.GetStatsInput{})
				return err
			},
		},
		{
			name: "KMS get key",
			path: "/api/v2/tenants/tenant-a/keys/key-a",
			call: func(ctx context.Context, client *http.Client, baseURL string) error {
				_, err := NewHttpKMSClient(client, baseURL).GetKey(ctx, services.GetKeyInput{Identifier: "key-a"})
				return err
			},
		},
		{
			name: "Device Manager get device",
			path: "/api/v2/tenants/tenant-a/devices/device-a",
			call: func(ctx context.Context, client *http.Client, baseURL string) error {
				_, err := NewHttpDeviceManagerClient(client, baseURL).GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: "device-a"})
				return err
			},
		},
		{
			name: "DMS get",
			path: "/api/v2/tenants/tenant-a/dms/dms-a",
			call: func(ctx context.Context, client *http.Client, baseURL string) error {
				_, err := NewHttpDMSManagerClient(client, baseURL).GetDMSByID(ctx, services.GetDMSByIDInput{ID: "dms-a"})
				return err
			},
		},
		{
			name: "VA get role",
			path: "/api/v2/tenants/tenant-a/roles/ca-ski-a",
			call: func(ctx context.Context, client *http.Client, baseURL string) error {
				_, err := NewHttpVAClient(client, baseURL).GetVARoleByID(ctx, services.GetVARoleInput{CASubjectKeyID: "ca-ski-a"})
				return err
			},
		},
		{
			name: "Alerts latest events",
			path: "/api/v2/tenants/tenant-a/events/latest",
			call: func(ctx context.Context, client *http.Client, baseURL string) error {
				_, err := NewHttpAlertsClient(client, baseURL).GetLatestEventsPerEventType(ctx, &services.GetLatestEventsPerEventTypeInput{})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var receivedPath string
			var receivedMethod string
			var receivedTenantID string
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				receivedPath = request.URL.Path
				receivedMethod = request.Method
				receivedTenantID = request.Header.Get(tenantIDHeader)
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(map[string]any{"list": []any{}, "next": ""})
			}))
			defer server.Close()

			if err := test.call(tenantContext, server.Client(), server.URL); err != nil {
				t.Fatalf("SDK request failed: %v", err)
			}
			if receivedPath != test.path || receivedMethod != http.MethodGet || receivedTenantID != "tenant-a" {
				t.Fatalf("expected GET %s with tenant header tenant-a, got %s %s tenant=%q", test.path, receivedMethod, receivedPath, receivedTenantID)
			}
		})
	}
}
