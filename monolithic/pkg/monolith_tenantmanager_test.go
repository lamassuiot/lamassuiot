package pkg

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devruntime"
)

// TestMonolithTenantManager recorre la tarea 8 de la spec 009 (requisitos
// 1.1, 1.2, 8.1–8.3): el Tenant Manager montado en el monolito y publicado en
// el proxy en /api/tenants/, con el provisioner del emisor local.
func TestMonolithTenantManager(t *testing.T) {
	m := startMonolith(t, "default", nil)
	issuer := m.rt.Issuer.Issuer()
	provisioner := m.token(t, devruntime.DefaultProvisionerSubject)
	const tm = "/api/tenants/api/v2"

	decode := func(t *testing.T, resp testResponse, out any) {
		t.Helper()
		if err := json.Unmarshal([]byte(resp.body), out); err != nil {
			t.Fatalf("respuesta no JSON: %v: %.300s", err, resp.body)
		}
	}

	t.Run("HealthThroughProxy", func(t *testing.T) {
		m.expect(t, http.StatusOK, http.MethodGet, "/api/tenants/health", "", "", nil)
	})

	t.Run("MyMembershipsWithTokenIs200", func(t *testing.T) {
		resp := m.expect(t, http.StatusOK, http.MethodGet, tm+"/me/memberships", m.token(t, "nobody"), "", nil)
		var body struct {
			Memberships []any `json:"memberships"`
		}
		decode(t, resp, &body)
		if len(body.Memberships) != 0 {
			t.Errorf("una identidad nueva tiene memberships: %v", body.Memberships)
		}
		m.expect(t, http.StatusUnauthorized, http.MethodGet, tm+"/me/memberships", "", "", nil)
	})

	t.Run("NonProvisionerCannotProvision", func(t *testing.T) {
		m.expect(t, http.StatusForbidden, http.MethodPost, tm+"/provisioning/organizations", m.token(t, "alice"), `{"name":"Org by alice"}`, nil)
	})

	var tenantA, tenantB struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	t.Run("ProvisionerCreatesOrganizationAndTenantsActive", func(t *testing.T) {
		resp := m.expect(t, http.StatusCreated, http.MethodPost, tm+"/provisioning/organizations", provisioner, `{"name":"TM test org"}`, nil)
		var org struct {
			ID string `json:"id"`
		}
		decode(t, resp, &org)
		for name, out := range map[string]*struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}{"A": &tenantA, "B": &tenantB} {
			admin := map[string]string{"A": "tm-admin-a", "B": "tm-admin-b"}[name]
			body := fmt.Sprintf(`{"organization_id":%q,"name":"TM tenant %s","initial_admin":{"issuer":%q,"subject":%q}}`, org.ID, name, issuer, admin)
			resp := m.expect(t, http.StatusCreated, http.MethodPost, tm+"/provisioning/tenants", provisioner, body, nil)
			decode(t, resp, out)
			if out.Status != "ACTIVE" {
				t.Errorf("tenant %s nace %q, se esperaba ACTIVE", name, out.Status)
			}
		}
	})
	if tenantA.ID == "" || tenantB.ID == "" {
		t.Fatal("sin tenants A y B no se puede seguir")
	}

	t.Run("ProvisionerHasNoAccessToTenantData", func(t *testing.T) {
		m.expect(t, http.StatusForbidden, http.MethodGet, "/api/ca/api/v2/tenants/"+tenantA.ID+"/cas", provisioner, "", nil)
	})

	t.Run("TenantAdminSeesItsMembership", func(t *testing.T) {
		resp := m.expect(t, http.StatusOK, http.MethodGet, tm+"/me/memberships", m.token(t, "tm-admin-a"), "", nil)
		var body struct {
			Memberships []struct {
				TenantID string `json:"tenant_id"`
				Role     string `json:"role"`
			} `json:"memberships"`
		}
		decode(t, resp, &body)
		if len(body.Memberships) != 1 || body.Memberships[0].TenantID != tenantA.ID || body.Memberships[0].Role != "tenant_admin" {
			t.Errorf("memberships de tm-admin-a: %+v", body.Memberships)
		}
	})

	t.Run("TenantAdminGrantsPKIAdminAndCannotTouchOwnMembership", func(t *testing.T) {
		admin := m.token(t, "tm-admin-a")
		memberships := "/api/tenants/api/v2/tenants/" + tenantA.ID + "/memberships"
		m.expect(t, http.StatusCreated, http.MethodPost, memberships, admin,
			fmt.Sprintf(`{"issuer":%q,"subject":"tm-pki-a","role":"pki_admin"}`, issuer), nil)

		resp := m.expect(t, http.StatusOK, http.MethodGet, memberships, admin, "", nil)
		var list struct {
			Memberships []struct {
				ID      string `json:"id"`
				Subject string `json:"identity_subject"`
			} `json:"memberships"`
		}
		decode(t, resp, &list)
		own := ""
		for _, membership := range list.Memberships {
			if membership.Subject == "tm-admin-a" {
				own = membership.ID
			}
		}
		if own == "" {
			t.Fatalf("no aparece la membership propia en %s", resp.body)
		}
		m.expect(t, http.StatusConflict, http.MethodPatch, memberships+"/"+own, admin, `{"role":"viewer"}`, nil)

		// El pki_admin concedido ya opera en A y no en B.
		m.expect(t, http.StatusOK, http.MethodGet, "/api/ca/api/v2/tenants/"+tenantA.ID+"/cas", m.token(t, "tm-pki-a"), "", nil)
		m.expect(t, http.StatusForbidden, http.MethodGet, "/api/ca/api/v2/tenants/"+tenantB.ID+"/cas", m.token(t, "tm-pki-a"), "", nil)
	})

	t.Run("TenantAdminOfACannotManageB", func(t *testing.T) {
		m.expect(t, http.StatusForbidden, http.MethodGet, "/api/tenants/api/v2/tenants/"+tenantB.ID+"/memberships", m.token(t, "tm-admin-a"), "", nil)
	})
}
