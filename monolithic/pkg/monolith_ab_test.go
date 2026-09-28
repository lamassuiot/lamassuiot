//go:build monolith

package pkg

// Escenario A/B de extremo a extremo contra el monolito (spec 009, tarea 13;
// requisitos 1.1, 2.2, 5.1–5.5 y 8.1–8.6). Se ejecuta con:
//
//	CGO_ENABLED=1 go -C monolithic test -tags monolith ./... -run TestMonolithTenantIsolationAB -count=1 -v -timeout 40m
//
// El monolito es el mismo que monta cmd/development (siete servicios, proxy,
// JWT con el emisor local, Tenant Manager, mTLS interno, v1 por defecto),
// con eventbus en memoria y crypto filesystem. La guía manual equivalente
// está en monolithic/README.md.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	pgconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devruntime"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devstorage"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

func TestMonolithTenantIsolationAB(t *testing.T) {
	m := startMonolith(t, "default", nil)
	issuer := m.rt.Issuer.Issuer()
	const tm = "/api/tenants/api/v2"
	provisioner := m.token(t, devruntime.DefaultProvisionerSubject)

	decode := func(t *testing.T, resp testResponse, out any) {
		t.Helper()
		if err := json.Unmarshal([]byte(resp.body), out); err != nil {
			t.Fatalf("respuesta no JSON: %v: %.300s", err, resp.body)
		}
	}
	step := func(t *testing.T, want int, method, path, subject, body string, headers map[string]string) testResponse {
		t.Helper()
		token := ""
		if subject != "" {
			token = m.token(t, subject)
		}
		resp := m.expect(t, want, method, path, token, body, headers)
		who := subject
		if who == "" {
			who = "(sin token)"
		}
		t.Logf("%-6s %-70s %-12s → %d", method, path, who, resp.status)
		return resp
	}

	t.Run("01_HealthOfTheSevenServicesThroughTheProxy", func(t *testing.T) {
		for _, svc := range []string{"kms", "ca", "va", "devmanager", "dmsmanager", "alerts", "tenants"} {
			step(t, http.StatusOK, http.MethodGet, "/api/"+svc+"/health", "", "", nil)
		}
	})

	var orgID string
	tenants := map[string]string{}
	t.Run("02_ProvisionerCreatesOrganizationAndTenantsABActive", func(t *testing.T) {
		var org struct {
			ID string `json:"id"`
		}
		decode(t, step(t, http.StatusCreated, http.MethodPost, tm+"/provisioning/organizations", devruntime.DefaultProvisionerSubject, `{"name":"AB org"}`, nil), &org)
		orgID = org.ID
		for _, name := range []string{"A", "B"} {
			body := fmt.Sprintf(`{"organization_id":%q,"name":"Tenant %s","initial_admin":{"issuer":%q,"subject":"admin-%s"}}`, org.ID, name, issuer, strings.ToLower(name))
			var tenant struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			}
			decode(t, step(t, http.StatusCreated, http.MethodPost, tm+"/provisioning/tenants", devruntime.DefaultProvisionerSubject, body, nil), &tenant)
			if tenant.Status != "ACTIVE" {
				t.Errorf("tenant %s nace %q, se esperaba ACTIVE", name, tenant.Status)
			}
			tenants[name] = tenant.ID
		}
	})
	if tenants["A"] == "" || tenants["B"] == "" {
		t.Fatal("sin tenants A y B no se puede seguir")
	}
	casOf := func(tenant string) string { return "/api/ca/api/v2/tenants/" + tenants[tenant] + "/cas" }
	membershipsOf := func(tenant string) string { return tm + "/tenants/" + tenants[tenant] + "/memberships" }

	t.Run("03_ProvisionerCannotReadTenantData", func(t *testing.T) {
		m.expect(t, http.StatusForbidden, http.MethodGet, casOf("A"), provisioner, "", nil)
		t.Logf("GET    %-70s %-12s → 403", casOf("A"), "provisioner")
	})

	t.Run("04_TenantAdminsGrantRolesAndCannotTouchTheirOwnMembership", func(t *testing.T) {
		for _, grant := range []struct{ tenant, admin, subject, role string }{
			{"A", "admin-a", "alice", "pki_admin"},
			{"B", "admin-b", "bob", "pki_admin"},
			{"A", "admin-a", "carol", "viewer"},
		} {
			step(t, http.StatusCreated, http.MethodPost, membershipsOf(grant.tenant), grant.admin,
				fmt.Sprintf(`{"issuer":%q,"subject":%q,"role":%q}`, issuer, grant.subject, grant.role), nil)
		}
		var list struct {
			Memberships []struct {
				ID      string `json:"id"`
				Subject string `json:"identity_subject"`
			} `json:"memberships"`
		}
		decode(t, step(t, http.StatusOK, http.MethodGet, membershipsOf("A"), "admin-a", "", nil), &list)
		own := ""
		for _, membership := range list.Memberships {
			if membership.Subject == "admin-a" {
				own = membership.ID
			}
		}
		if own == "" {
			t.Fatal("no aparece la membership de admin-a")
		}
		step(t, http.StatusConflict, http.MethodPatch, membershipsOf("A")+"/"+own, "admin-a", `{"role":"viewer"}`, nil)
		step(t, http.StatusForbidden, http.MethodGet, membershipsOf("B"), "admin-a", "", nil)
	})

	cas := map[string]string{}
	t.Run("05_EachPKIAdminCreatesAProfileAndACAInItsTenant", func(t *testing.T) {
		cas["A"] = m.createCA(t, orgID, tenants["A"], "alice", "CA of tenant A").ID
		cas["B"] = m.createCA(t, orgID, tenants["B"], "bob", "CA of tenant B").ID
		t.Logf("CA de A: %s (alice); CA de B: %s (bob)", cas["A"], cas["B"])
	})
	if cas["A"] == "" || cas["B"] == "" {
		t.Fatal("sin las CAs de A y B no se puede seguir")
	}

	t.Run("06_EachCAAppearsOnlyInTheListOfItsTenant", func(t *testing.T) {
		for _, c := range []struct{ tenant, subject, own, other string }{
			{"A", "alice", cas["A"], cas["B"]},
			{"B", "bob", cas["B"], cas["A"]},
		} {
			resp := step(t, http.StatusOK, http.MethodGet, casOf(c.tenant), c.subject, "", nil)
			if !strings.Contains(resp.body, c.own) || strings.Contains(resp.body, c.other) {
				t.Errorf("listado de %s: se esperaba %s y no %s: %.500s", c.tenant, c.own, c.other, resp.body)
			}
		}
	})

	t.Run("07_Requirement5Cases", func(t *testing.T) {
		// 5.2: otro tenant → 403.
		step(t, http.StatusForbidden, http.MethodGet, casOf("B"), "alice", "", nil)
		// 5.3: el recurso de A pedido desde B da el mismo «no encontrado»
		// que un ID inexistente.
		foreign := step(t, http.StatusNotFound, http.MethodGet, casOf("B")+"/"+cas["A"], "bob", "", nil)
		missing := step(t, http.StatusNotFound, http.MethodGet, casOf("B")+"/does-not-exist", "bob", "", nil)
		if strings.ReplaceAll(foreign.body, cas["A"], "X") != strings.ReplaceAll(missing.body, "does-not-exist", "X") {
			t.Errorf("respuestas distintas: %q frente a %q", foreign.body, missing.body)
		}
		// 5.4: ruta y cabecera contradictorias → 400.
		step(t, http.StatusBadRequest, http.MethodGet, casOf("A"), "alice", "", map[string]string{"X-Tenant-ID": tenants["B"]})
		// 5.5: rol sin el permiso (viewer no tiene ca.write) → 403; lectura → 200.
		step(t, http.StatusOK, http.MethodGet, casOf("A"), "carol", "", nil)
		step(t, http.StatusForbidden, http.MethodPost, casOf("A"), "carol", `{}`, nil)
		// Sin token → 401.
		step(t, http.StatusUnauthorized, http.MethodGet, casOf("A"), "", "", nil)
	})

	t.Run("08_V1Is503ByDefault", func(t *testing.T) {
		step(t, http.StatusServiceUnavailable, http.MethodGet, "/api/ca/v1/cas", "alice", "", nil)
	})

	t.Run("09_IsolationIsAlsoInTheDatabaseAsLamassuApp", func(t *testing.T) {
		app, err := cconfig.DecodeStruct[pgconfig.PostgresPSEConfig](m.pg.storage.Config)
		if err != nil {
			t.Fatal(err)
		}
		if app.Username != devstorage.AppRole {
			t.Fatalf("los servicios no usan %s sino %s", devstorage.AppRole, app.Username)
		}
		db, err := gorm.Open(postgres.Open(fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=ca sslmode=disable",
			app.Hostname, app.Port, app.Username, app.Password)), &gorm.Config{Logger: gormLogger.Discard})
		if err != nil {
			t.Fatal(err)
		}
		if sqlDB, err := db.DB(); err == nil {
			defer sqlDB.Close()
		}

		var withoutTenant int64
		if err := db.Raw("SELECT count(*) FROM ca_certificates").Scan(&withoutTenant).Error; err != nil {
			t.Fatal(err)
		}
		t.Logf("lamassu_app sin app.tenant_id: %d filas en ca_certificates", withoutTenant)
		if withoutTenant != 0 {
			t.Errorf("lamassu_app sin app.tenant_id ve %d filas", withoutTenant)
		}
		for _, c := range []struct{ tenant, own, other string }{{"A", cas["A"], cas["B"]}, {"B", cas["B"], cas["A"]}} {
			err := db.Transaction(func(tx *gorm.DB) error {
				if err := tx.Exec("SELECT set_config('app.tenant_id', ?, true)", tenants[c.tenant]).Error; err != nil {
					return err
				}
				var ids []string
				if err := tx.Raw("SELECT id FROM ca_certificates").Scan(&ids).Error; err != nil {
					return err
				}
				t.Logf("lamassu_app con app.tenant_id = %s: %v", c.tenant, ids)
				if len(ids) != 1 || ids[0] != c.own {
					t.Errorf("con app.tenant_id = %s se ven %v, se esperaba solo %s", c.tenant, ids, c.own)
				}
				res := tx.Exec("UPDATE ca_certificates SET tenant_id = ? WHERE id = ?", tenants[c.tenant], c.other)
				if res.Error != nil {
					return res.Error
				}
				if res.RowsAffected != 0 {
					t.Errorf("desde %s un UPDATE de la CA del otro tenant modificó %d filas", c.tenant, res.RowsAffected)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}

		// Como administrador (sin RLS) las dos filas existen, cada una en su tenant.
		var rows []struct {
			ID       string
			TenantID string
		}
		if err := m.pg.adminDB(t, "ca").Raw("SELECT id, tenant_id FROM ca_certificates WHERE id IN (?, ?)", cas["A"], cas["B"]).Scan(&rows).Error; err != nil {
			t.Fatal(err)
		}
		t.Logf("administrador: %+v", rows)
		for _, row := range rows {
			if (row.ID == cas["A"] && row.TenantID != tenants["A"]) || (row.ID == cas["B"] && row.TenantID != tenants["B"]) {
				t.Errorf("la CA %s está en el tenant %s", row.ID, row.TenantID)
			}
		}
		if len(rows) != 2 {
			t.Errorf("el administrador ve %d de las 2 CAs", len(rows))
		}
	})
}
