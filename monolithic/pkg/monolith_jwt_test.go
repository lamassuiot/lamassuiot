package pkg

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devissuer"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devpki"
)

// TestMonolithJWT recorre la tarea 7 de la spec 009 (requisitos 4.1, 4.3,
// 5.1–5.5) con memberships sembradas en controlplane, sin Tenant Manager.
func TestMonolithJWT(t *testing.T) {
	m := startMonolith(t, "default", nil)
	issuer := m.rt.Issuer.Issuer()
	m.pg.seedMembership(t, testOrgA, testTenantA, issuer, "alice", "pki_admin")
	m.pg.seedMembership(t, testOrgA, testTenantA, issuer, "victor", "viewer")
	m.pg.seedTenant(t, testOrgB, testTenantB)

	casA := "/api/ca/api/v2/tenants/" + testTenantA + "/cas"
	casB := "/api/ca/api/v2/tenants/" + testTenantB + "/cas"

	// Cada servicio valida el token del emisor local (confía en su CA sin
	// SSL_CERT_DIR) y rechaza la petición sin token. KMS solo concede sus
	// operaciones a un pki_admin con actor SERVICE y el scope de la operación
	// (matriz RBAC de G2), así que se prueba con esa identidad.
	t.Run("JWTValidatedByEveryService", func(t *testing.T) {
		m.pg.seedMembership(t, testOrgA, testTenantA, issuer, "kms-client", "pki_admin")
		serviceToken, err := m.rt.Issuer.Token(devissuer.TokenRequest{Subject: "kms-client", ActorType: "SERVICE", Scope: "key.read"})
		if err != nil {
			t.Fatal(err)
		}
		keysA := "/api/kms/api/v2/tenants/" + testTenantA + "/keys"
		for path, token := range map[string]string{
			keysA: serviceToken,
			casA:  m.token(t, "alice"),
			"/api/va/api/v2/tenants/" + testTenantA + "/roles/00":          m.token(t, "alice"),
			"/api/devmanager/api/v2/tenants/" + testTenantA + "/devices":   m.token(t, "alice"),
			"/api/dmsmanager/api/v2/tenants/" + testTenantA + "/dms":       m.token(t, "alice"),
			"/api/alerts/api/v2/tenants/" + testTenantA + "/events/latest": m.token(t, "alice"),
		} {
			m.expect(t, http.StatusUnauthorized, http.MethodGet, path, "", "", nil)
			if resp := m.do(t, http.MethodGet, path, token, "", nil); resp.status == http.StatusUnauthorized || resp.status == http.StatusForbidden || resp.status >= 500 {
				t.Errorf("GET %s con token válido y membership pki_admin en A: estado %d; cuerpo: %.300s", path, resp.status, resp.body)
			}
		}
		// Un humano pki_admin no tiene operaciones de KMS (RBAC, 403).
		m.expect(t, http.StatusForbidden, http.MethodGet, keysA, m.token(t, "alice"), "", nil)
	})

	t.Run("NoTokenIs401", func(t *testing.T) {
		m.expect(t, http.StatusUnauthorized, http.MethodGet, casA, "", "", nil)
	})

	t.Run("TamperedSignatureIs401", func(t *testing.T) {
		token := m.token(t, "alice")
		parts := strings.Split(token, ".")
		sig := []byte(parts[2])
		if sig[10] == 'A' {
			sig[10] = 'B'
		} else {
			sig[10] = 'A'
		}
		m.expect(t, http.StatusUnauthorized, http.MethodGet, casA, "", "", map[string]string{
			"Authorization": "Bearer " + parts[0] + "." + parts[1] + "." + string(sig),
		})
	})

	t.Run("UnconfiguredIssuerIs401", func(t *testing.T) {
		ca, err := devpki.NewCA("rogue CA")
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := ca.Issue("rogue-issuer")
		if err != nil {
			t.Fatal(err)
		}
		rogue, err := devissuer.Start(devissuer.Options{TLSCertificate: leaf.TLS})
		if err != nil {
			t.Fatal(err)
		}
		defer rogue.Close()
		token, err := rogue.Token(devissuer.TokenRequest{Subject: "alice", ActorType: "HUMAN"})
		if err != nil {
			t.Fatal(err)
		}
		m.expect(t, http.StatusUnauthorized, http.MethodGet, casA, token, "", nil)
	})

	t.Run("ValidTokenWithoutMembershipIs403", func(t *testing.T) {
		m.expect(t, http.StatusForbidden, http.MethodGet, casA, m.token(t, "mallory"), "", nil)
	})

	t.Run("PKIAdminInAListsCAsOfA", func(t *testing.T) {
		m.expect(t, http.StatusOK, http.MethodGet, casA, m.token(t, "alice"), "", nil)
	})

	t.Run("ExternalIssuerAcceptedAlongsideLocalIssuer", func(t *testing.T) {
		m.pg.seedMembership(t, testOrgA, testTenantA, m.external.Issuer(), "erin", "pki_admin")
		token, err := m.external.Token(devissuer.TokenRequest{Subject: "erin", ActorType: "HUMAN"})
		if err != nil {
			t.Fatal(err)
		}
		m.expect(t, http.StatusOK, http.MethodGet, casA, token, "", nil)
		m.expect(t, http.StatusOK, http.MethodGet, casA, m.token(t, "alice"), "", nil)
	})

	t.Run("PKIAdminOfAInBIs403", func(t *testing.T) {
		m.expect(t, http.StatusForbidden, http.MethodGet, casB, m.token(t, "alice"), "", nil)
	})

	t.Run("ContradictoryTenantHeaderIs400", func(t *testing.T) {
		m.expect(t, http.StatusBadRequest, http.MethodGet, casA, m.token(t, "alice"), "", map[string]string{"X-Tenant-ID": testTenantB})
	})

	t.Run("RoleWithoutPermissionIs403", func(t *testing.T) {
		m.expect(t, http.StatusOK, http.MethodGet, casA, m.token(t, "victor"), "", nil)
		m.expect(t, http.StatusForbidden, http.MethodPost, casA, m.token(t, "victor"), `{}`, nil)
	})
}
