package x509engines

import (
	"context"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
)

func TestVAURLsIncludeTheTenantOfTheContext(t *testing.T) {
	tenantCtx := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org", TenantID: "tenant-a", ActorID: "actor", ActorType: "SERVICE",
		CorrelationID: "corr", Source: "test", TenantStatus: core.TenantActive, Validated: true,
	})
	if got := CRLURL(tenantCtx, "va.example.com", "abcd"); got != "http://va.example.com/tenants/tenant-a/crl/abcd" {
		t.Fatalf("unexpected tenant CRL URL %q", got)
	}
	if got := OCSPURL(tenantCtx, "va.example.com"); got != "http://va.example.com/tenants/tenant-a/ocsp" {
		t.Fatalf("unexpected tenant OCSP URL %q", got)
	}
	if got := CRLURL(context.Background(), "va.example.com", "abcd"); got != "http://va.example.com/crl/abcd" {
		t.Fatalf("unexpected legacy CRL URL %q", got)
	}
	if got := OCSPURL(context.Background(), "va.example.com"); got != "http://va.example.com/ocsp" {
		t.Fatalf("unexpected legacy OCSP URL %q", got)
	}
}
