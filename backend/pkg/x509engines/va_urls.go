package x509engines

import (
	"context"
	"fmt"
	"net/url"

	core "github.com/lamassuiot/lamassuiot/core/v3"
)

// CRLURL and OCSPURL build the public VA URLs embedded in certificates and
// CRLs. With a tenant in the context they include it (/tenants/{id}/...), so a
// relying party reaches the tenant's CRL/OCSP without any cross-tenant lookup.
// Without a tenant they keep the legacy shape, served for the default tenant.
func CRLURL(ctx context.Context, domain string, caSKI string) string {
	if tenantID, ok := vaTenantID(ctx); ok {
		return fmt.Sprintf("http://%s/tenants/%s/crl/%s", domain, url.PathEscape(tenantID), caSKI)
	}
	return fmt.Sprintf("http://%s/crl/%s", domain, caSKI)
}

func OCSPURL(ctx context.Context, domain string) string {
	if tenantID, ok := vaTenantID(ctx); ok {
		return fmt.Sprintf("http://%s/tenants/%s/ocsp", domain, url.PathEscape(tenantID))
	}
	return fmt.Sprintf("http://%s/ocsp", domain)
}

func vaTenantID(ctx context.Context) (string, bool) {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return "", false
	}
	return tenantContext.TenantID, true
}
