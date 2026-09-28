package pkg

// Arnés de las pruebas con Docker del monolito ensamblado (spec 009, tareas
// 7–10): un PostgreSQL por proceso de prueba, preparado con devstorage, y uno
// o más monolitos sobre él. Los servicios no se pueden parar, así que cada
// monolito vive hasta el final del proceso; TestMain borra el contenedor y los
// directorios temporales (solo los propios, nunca por etiqueta).

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	pgconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devissuer"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devpki"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devruntime"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devstorage"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

const (
	testOrgA    = "aaaaaaaa-0000-0000-0000-00000000000a"
	testOrgB    = "bbbbbbbb-0000-0000-0000-00000000000b"
	testTenantA = "aaaaaaaa-1111-1111-1111-11111111111a"
	testTenantB = "bbbbbbbb-2222-2222-2222-22222222222b"
)

var (
	harnessMu       sync.Mutex
	harnessCleanups []func()
	sharedPostgres  *testPostgres
	monoliths       = map[string]*testMonolith{}
)

type testPostgres struct {
	admin   pgconfig.PostgresPSEConfig
	storage cconfig.PluggableStorageEngine
}

type testMonolith struct {
	name     string
	httpsURL string
	rt       *devruntime.Runtime
	external *devissuer.Issuer
	conf     MonolithicConfig
	pg       *testPostgres
	client   *http.Client
}

func TestMain(m *testing.M) {
	code := m.Run()
	harnessMu.Lock()
	for i := len(harnessCleanups) - 1; i >= 0; i-- {
		harnessCleanups[i]()
	}
	harnessMu.Unlock()
	os.Exit(code)
}

func addHarnessCleanup(f func()) { harnessCleanups = append(harnessCleanups, f) }

// postgresForTests lanza (una vez por proceso) un PostgreSQL en Docker y lo
// prepara como el monolito: controlplane, migraciones y lamassu_app.
func postgresForTests(t *testing.T) *testPostgres {
	t.Helper()
	if sharedPostgres != nil {
		return sharedPostgres
	}
	ctx := context.Background()
	pg, err := devstorage.Start(ctx, devstorage.StartOptions{StandardPort: false})
	if err != nil {
		t.Fatalf("no se pudo lanzar PostgreSQL (¿contención de Docker?): %v", err)
	}
	addHarnessCleanup(pg.Cleanup)
	logger := chelpers.SetupLogger(cconfig.Info, "Monolith test", "PostgreSQL")
	prepared, err := devstorage.Prepare(ctx, logger, pg.Admin)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	sharedPostgres = &testPostgres{admin: pg.Admin, storage: prepared.Storage}
	return sharedPostgres
}

// startMonolith arranca (una vez por nombre) un monolito multitenant con el
// emisor local, eventbus desactivado y crypto filesystem. mutate ajusta la
// configuración antes de ensamblar.
func startMonolith(t *testing.T, name string, mutate func(*MonolithicConfig)) *testMonolith {
	t.Helper()
	harnessMu.Lock()
	defer harnessMu.Unlock()
	if m, ok := monoliths[name]; ok {
		return m
	}
	pg := postgresForTests(t)

	dir, err := os.MkdirTemp("", "lamassu-monolith-test-")
	if err != nil {
		t.Fatal(err)
	}
	addHarnessCleanup(func() { _ = os.RemoveAll(dir) })

	// IdP «externo»: otro emisor con su propia CA, pasado como -issuer y
	// -issuer-ca-file (requisito 4.5).
	extCA, err := devpki.NewCA("external IdP CA")
	if err != nil {
		t.Fatal(err)
	}
	extLeaf, err := extCA.Issue("external-idp")
	if err != nil {
		t.Fatal(err)
	}
	external, err := devissuer.Start(devissuer.Options{TLSCertificate: extLeaf.TLS})
	if err != nil {
		t.Fatal(err)
	}
	addHarnessCleanup(func() { _ = external.Close() })
	extCAFile := filepath.Join(dir, "external-ca.crt")
	if err := devpki.WriteFile(extCAFile, extCA.CertPEM()); err != nil {
		t.Fatal(err)
	}

	rt, err := devruntime.Start(devruntime.Options{
		Dir:             filepath.Join(dir, "runtime"),
		DevIssuer:       true,
		ExternalIssuers: []cconfig.HttpServerJWTIssuer{{Issuer: external.Issuer(), JWKSURL: external.JWKSURL()}},
		ExternalCAFiles: []string{extCAFile},
	})
	if err != nil {
		t.Fatalf("devruntime.Start: %v", err)
	}
	addHarnessCleanup(func() { _ = rt.Close() })

	disabledBus := cconfig.EventBusEngine{Enabled: false, Provider: cconfig.Amqp, Config: map[string]interface{}{}}
	mt := rt.Multitenant
	mt.Provisioners = rt.DefaultProvisioners()
	conf := MonolithicConfig{
		Logs:                  cconfig.Logging{Level: cconfig.Info},
		PublisherEventBus:     disabledBus,
		SubscriberEventBus:    disabledBus,
		SubscriberDLQEventBus: disabledBus,
		Storage:               pg.storage,
		CryptoEngines: []cconfig.CryptoEngineConfig{{
			ID:       "filesystem-test-1",
			Type:     cconfig.FilesystemProvider,
			Metadata: map[string]interface{}{},
			Config:   map[string]interface{}{"storage_directory": filepath.Join(dir, "crypto")},
		}},
		Monitoring:   cconfig.MonitoringJob{Enabled: false, Frequency: "2m"},
		Domains:      []string{"localhost"},
		AssemblyMode: Http,
		VAStorageDir: filepath.Join(dir, "va"),
		Multitenant:  mt,
	}
	if mutate != nil {
		mutate(&conf)
	}

	_, httpsPort, err := RunMonolithicLamassuPKI(conf)
	if err != nil {
		t.Fatalf("RunMonolithicLamassuPKI: %v", err)
	}
	m := &testMonolith{
		name:     name,
		httpsURL: fmt.Sprintf("https://127.0.0.1:%d", httpsPort),
		rt:       rt,
		external: external,
		conf:     conf,
		pg:       pg,
		client: &http.Client{
			Timeout: 30 * time.Second,
			// El proxy usa un certificado autofirmado (como hoy en el monolito).
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
	monoliths[name] = m
	return m
}

func (m *testMonolith) token(t *testing.T, subject string) string {
	t.Helper()
	token, err := m.rt.Issuer.Token(devissuer.TokenRequest{Subject: subject, ActorType: "HUMAN"})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type testResponse struct {
	status int
	header http.Header
	body   string
}

func (m *testMonolith) do(t *testing.T, method, path, token string, body string, headers map[string]string) testResponse {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, m.httpsURL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return testResponse{status: resp.StatusCode, header: resp.Header, body: string(raw)}
}

func (m *testMonolith) expect(t *testing.T, want int, method, path, token, body string, headers map[string]string) testResponse {
	t.Helper()
	resp := m.do(t, method, path, token, body, headers)
	if resp.status != want {
		t.Errorf("%s %s: estado %d, se esperaba %d; cuerpo: %.300s", method, path, resp.status, want, resp.body)
	}
	return resp
}

func (pg *testPostgres) adminDB(t *testing.T, database string) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		pg.admin.Hostname, pg.admin.Port, pg.admin.Username, pg.admin.Password, database)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormLogger.Discard})
	if err != nil {
		t.Fatalf("no se pudo abrir %s como administrador: %v", database, err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	})
	return db
}

// seedMembership crea (si falta) la organización, el tenant ACTIVE, la
// identidad y una membership ACTIVE directamente en controlplane, como
// administrador. Sirve para probar JWT antes de montar el Tenant Manager.
func (pg *testPostgres) seedMembership(t *testing.T, orgID, tenantID, issuer, subject, role string) {
	t.Helper()
	db := pg.adminDB(t, "controlplane")
	stmts := []struct {
		sql  string
		args []interface{}
	}{
		{`INSERT INTO organizations (id, name) VALUES (?, ?) ON CONFLICT (id) DO NOTHING`, []interface{}{orgID, "org-" + orgID}},
		{`INSERT INTO tenants (id, organization_id, name, status, isolation_mode) VALUES (?, ?, ?, 'ACTIVE', 'POOLED') ON CONFLICT (id) DO NOTHING`, []interface{}{tenantID, orgID, "tenant-" + tenantID}},
		{`INSERT INTO identities (issuer, subject) VALUES (?, ?) ON CONFLICT DO NOTHING`, []interface{}{issuer, subject}},
		{`INSERT INTO memberships (id, organization_id, tenant_id, identity_issuer, identity_subject, role, status) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
		  ON CONFLICT (tenant_id, identity_issuer, identity_subject) DO UPDATE SET role = EXCLUDED.role, status = 'ACTIVE'`,
			[]interface{}{uuid.NewString(), orgID, tenantID, issuer, subject, role}},
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt.sql, stmt.args...).Error; err != nil {
			t.Fatalf("siembra de membership: %v", err)
		}
	}
}

// seedTenant crea la organización y el tenant sin memberships.
func (pg *testPostgres) seedTenant(t *testing.T, orgID, tenantID string) {
	t.Helper()
	db := pg.adminDB(t, "controlplane")
	if err := db.Exec(`INSERT INTO organizations (id, name) VALUES (?, ?) ON CONFLICT (id) DO NOTHING`, orgID, "org-"+orgID).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO tenants (id, organization_id, name, status, isolation_mode) VALUES (?, ?, ?, 'ACTIVE', 'POOLED') ON CONFLICT (id) DO NOTHING`,
		tenantID, orgID, "tenant-"+tenantID).Error; err != nil {
		t.Fatal(err)
	}
}
