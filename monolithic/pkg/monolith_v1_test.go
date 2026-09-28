package pkg

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/monoconfig"
)

const (
	defaultOrganization = "00000000-0000-0000-0000-000000000001"
	defaultTenant       = "00000000-0000-0000-0000-000000000002"
)

// TestMonolithV1 recorre la tarea 10 de la spec 009 (requisitos 6.1–6.3, P3).
func TestMonolithV1(t *testing.T) {
	t.Run("V1Is503ByDefault", func(t *testing.T) {
		m := startMonolith(t, "default", nil)
		m.pg.seedMembership(t, defaultOrganization, defaultTenant, m.rt.Issuer.Issuer(), "alice", "pki_admin")
		for _, token := range []string{"", m.token(t, "alice")} {
			resp := m.expect(t, http.StatusServiceUnavailable, http.MethodGet, "/api/ca/v1/cas", token, "", nil)
			if !strings.Contains(resp.body, "v1 compatibility is not configured") {
				t.Errorf("cuerpo %q, se esperaba «v1 compatibility is not configured»", resp.body)
			}
		}
	})

	t.Run("V1ServedInTheGivenTenantWithDeprecationHeaders", func(t *testing.T) {
		// La fecha la da la prueba: el monolito no tiene ninguna por defecto.
		sunset := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
		m := startMonolith(t, "v1", func(conf *MonolithicConfig) {
			conf.Multitenant.V1 = monoconfig.V1Config{DefaultTenantID: defaultTenant, SunsetAt: sunset}
		})
		issuer := m.rt.Issuer.Issuer()
		m.pg.seedMembership(t, defaultOrganization, defaultTenant, issuer, "v1-user", "pki_admin")

		resp := m.expect(t, http.StatusOK, http.MethodGet, "/api/ca/v1/cas", m.token(t, "v1-user"), "", nil)
		if resp.header.Get("Deprecation") == "" {
			t.Error("falta la cabecera Deprecation")
		}
		if got := resp.header.Get("Sunset"); got != sunset.Format(http.TimeFormat) {
			t.Errorf("Sunset %q, se esperaba %q", got, sunset.Format(http.TimeFormat))
		}
		if resp.header.Get("Link") == "" {
			t.Error("falta la cabecera Link")
		}

		// v1 sigue exigiendo identidad y membership en el tenant de v1.
		m.expect(t, http.StatusUnauthorized, http.MethodGet, "/api/ca/v1/cas", "", "", nil)
		m.expect(t, http.StatusForbidden, http.MethodGet, "/api/ca/v1/cas", m.token(t, "no-membership"), "", nil)
		// Una cabecera de otro tenant en v1 se rechaza.
		m.expect(t, http.StatusBadRequest, http.MethodGet, "/api/ca/v1/cas", m.token(t, "v1-user"), "", map[string]string{"X-Tenant-ID": testTenantA})
	})
}
