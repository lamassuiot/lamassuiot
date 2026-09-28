package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devissuer"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devstorage"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/monoconfig"
)

// bannerReadyLine es la última línea del banner: el monolito ya atiende
// peticiones. Las pruebas de proceso la esperan.
const bannerReadyLine = "MONOLITH READY"

// bannerInfo es lo que describe el banner de arranque (requisito 10.4). No
// lleva ninguna clave privada: solo rutas, URL e identidades.
type bannerInfo struct {
	RuntimeDir          string
	ListenAddress       string
	HTTPSPort, HTTPPort int
	Issuers             []cconfig.HttpServerJWTIssuer
	LocalIssuer         *devissuer.Issuer
	Provisioners        []config.TenantManagerProvisioner
	V1                  monoconfig.V1Config
	Postgres            string
	Warnings            []string
}

func renderBanner(b bannerInfo) string {
	var sb strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&sb, format+"\n", args...) }
	rule := strings.Repeat("=", 78)

	line(rule)
	line(" LAMASSU MONOLITH - DEVELOPMENT ENVIRONMENT - NOT FOR PRODUCTION")
	line(rule)
	line("Profile: multitenant (JWT + membership + RBAC on v2 routes, RLS with the lamassu_app role, mTLS between services)")
	host := b.ListenAddress
	line("Proxy: https://%s and http://%s", net.JoinHostPort(host, fmt.Sprint(b.HTTPSPort)), net.JoinHostPort(host, fmt.Sprint(b.HTTPPort)))
	line("  prefixes /api/{kms,ca,va,devmanager,dmsmanager,alerts,tenants}/ as the Helm gateway; services and internal listeners on 127.0.0.1")
	line("Runtime directory (0700, deleted on Ctrl+C): %s", b.RuntimeDir)
	line("PostgreSQL: %s; services connect as %s (no superuser, no BYPASSRLS)", b.Postgres, devstorage.AppRole)

	line("Accepted JWT issuers:")
	for _, issuer := range b.Issuers {
		line("  - %s (JWKS %s)", issuer.Issuer, issuer.JWKSURL)
	}
	if b.LocalIssuer != nil {
		line("Local token issuer (127.0.0.1 only; any local process can get a token for any identity): %s", b.LocalIssuer.Issuer())
		line("  get a token: curl -s --cacert %s/monolith-ca.crt -X POST %s -d '{\"subject\":\"alice\",\"actor_type\":\"HUMAN\"}'", b.RuntimeDir, b.LocalIssuer.TokenURL())
	} else {
		line("local token issuer: disabled (-dev-issuer=false)")
	}

	if len(b.Provisioners) == 0 {
		line("Tenant provisioners: none: no tenant provisioner can create organizations or tenants (use -provisioner)")
	} else {
		line("Tenant provisioners:")
		for _, p := range b.Provisioners {
			line("  - %s | %s", p.Issuer, p.Subject)
		}
	}

	if b.V1.DefaultTenantID == "" {
		line("v1 API: disabled (503), as with the Helm chart; use -v1-default-tenant and -v1-sunset to serve it")
	} else {
		line("v1 API: served in tenant %s until %s (Deprecation, Sunset and Link headers)", b.V1.DefaultTenantID, b.V1.SunsetAt.Format(time.RFC3339))
	}

	for _, warning := range b.Warnings {
		line("WARNING: %s", warning)
	}
	line(rule)
	line(bannerReadyLine)
	return sb.String()
}
