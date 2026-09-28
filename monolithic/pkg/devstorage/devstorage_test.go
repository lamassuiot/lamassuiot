package devstorage

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	pgconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

// runBarePostgres lanza un PostgreSQL vacío, sin scripts de init: las bases
// las crea Prepare.
func runBarePostgres(t *testing.T) pgconfig.PostgresPSEConfig {
	t.Helper()
	cleanup, container, pool, err := dockerrunner.RunDocker(dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "14",
		Env:        []string{"POSTGRES_PASSWORD=admin-test"},
		Labels:     map[string]string{"group": "lamassuiot-test-fixture"},
	}, func(*docker.HostConfig) {})
	if err != nil {
		t.Fatalf("no se pudo lanzar PostgreSQL (¿contención de Docker?): %v", err)
	}
	t.Cleanup(func() { _ = cleanup() })

	port, _ := strconv.Atoi(container.GetPort("5432/tcp"))
	admin := pgconfig.PostgresPSEConfig{Hostname: "127.0.0.1", Port: port, Username: "postgres", Password: "admin-test"}
	if err := pool.Retry(func() error {
		db, err := open(admin, "postgres")
		if err != nil {
			return err
		}
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		return sqlDB.Ping()
	}); err != nil {
		t.Fatalf("PostgreSQL no quedó listo: %v", err)
	}
	return admin
}

func open(cfg pgconfig.PostgresPSEConfig, dbName string) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cfg.Hostname, cfg.Port, cfg.Username, cfg.Password, dbName)
	return gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormLogger.Discard})
}

func mustOpen(t *testing.T, cfg pgconfig.PostgresPSEConfig, dbName string) *gorm.DB {
	t.Helper()
	db, err := open(cfg, dbName)
	if err != nil {
		t.Fatalf("no se pudo abrir %s como %s: %v", dbName, cfg.Username, err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	})
	return db
}

func appConfig(t *testing.T, res *Result) pgconfig.PostgresPSEConfig {
	t.Helper()
	cfg, err := cconfig.DecodeStruct[pgconfig.PostgresPSEConfig](res.Storage.Config)
	if err != nil {
		t.Fatalf("config de servicio no decodificable: %v", err)
	}
	return cfg
}

func TestPrepareWithLamassuApp(t *testing.T) {
	admin := runBarePostgres(t)
	logger := chelpers.SetupLogger(cconfig.Info, "test", "devstorage")

	res, err := Prepare(context.Background(), logger, admin)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	app := appConfig(t, res)
	adminPG := mustOpen(t, admin, "postgres")

	t.Run("ServiceStorageUsesLamassuApp", func(t *testing.T) {
		if res.Storage.Provider != cconfig.Postgres {
			t.Errorf("provider %q", res.Storage.Provider)
		}
		if app.Username != AppRole || app.Password == "" || app.Password == admin.Password {
			t.Errorf("config de servicio con usuario %q y contraseña vacía o del administrador", app.Username)
		}
		if app.Hostname != admin.Hostname || app.Port != admin.Port {
			t.Errorf("config de servicio apunta a %s:%d", app.Hostname, app.Port)
		}
	})

	t.Run("LamassuAppIsNotSuperuserNorBypassRLS", func(t *testing.T) {
		var role struct {
			RolSuper     bool `gorm:"column:rolsuper"`
			RolBypassRLS bool `gorm:"column:rolbypassrls"`
		}
		if err := adminPG.Raw("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = ?", AppRole).Scan(&role).Error; err != nil {
			t.Fatal(err)
		}
		if role.RolSuper || role.RolBypassRLS {
			t.Errorf("lamassu_app: rolsuper=%v rolbypassrls=%v", role.RolSuper, role.RolBypassRLS)
		}
	})

	t.Run("AllDatabasesExist", func(t *testing.T) {
		for _, name := range Databases {
			var n int64
			adminPG.Raw("SELECT count(*) FROM pg_database WHERE datname = ?", name).Scan(&n)
			if n != 1 {
				t.Errorf("falta la base %s", name)
			}
		}
	})

	t.Run("ControlPlaneIsMigratedWithDefaultTenant", func(t *testing.T) {
		cp := mustOpen(t, admin, "controlplane")
		for _, version := range []int64{20260928120000, 20260928130000} {
			var n int64
			cp.Raw("SELECT count(*) FROM goose_db_version WHERE version_id = ? AND is_applied", version).Scan(&n)
			if n == 0 {
				t.Errorf("migración %d de controlplane sin aplicar", version)
			}
		}
		var n int64
		cp.Raw("SELECT count(*) FROM tenants WHERE id = ?", "00000000-0000-0000-0000-000000000002").Scan(&n)
		if n != 1 {
			t.Errorf("falta el tenant por defecto")
		}
	})

	t.Run("LamassuAppHasDMLOnEveryTable", func(t *testing.T) {
		for _, name := range Databases {
			db := mustOpen(t, admin, name)
			var missing []string
			db.Raw(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname <> 'goose_db_version'
				AND NOT has_table_privilege(?, c.oid, 'SELECT,INSERT,UPDATE,DELETE')`, AppRole).Scan(&missing)
			if len(missing) > 0 {
				t.Errorf("%s: lamassu_app sin permisos en %v", name, missing)
			}
		}
	})

	caAdmin := mustOpen(t, admin, "ca")
	if err := caAdmin.Exec("INSERT INTO certificates (serial_number, tenant_id) VALUES (?, ?), (?, ?)",
		"serial-a", tenantA, "serial-b", tenantB).Error; err != nil {
		t.Fatalf("insertar certificados de A y B como administrador: %v", err)
	}
	if err := caAdmin.Exec("INSERT INTO ca_certificates (serial_number, id, tenant_id) VALUES (?, ?, ?), (?, ?, ?)",
		"serial-a", "ca-a", tenantA, "serial-b", "ca-b", tenantB).Error; err != nil {
		t.Fatalf("insertar filas de A y B como administrador: %v", err)
	}
	caApp := mustOpen(t, app, "ca")

	t.Run("NoRowsWithoutTenant", func(t *testing.T) {
		var n int64
		if err := caApp.Raw("SELECT count(*) FROM ca_certificates").Scan(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("lamassu_app sin app.tenant_id ve %d filas, se esperaban 0", n)
		}
	})

	t.Run("CrossTenantUpdateTouchesNoRows", func(t *testing.T) {
		err := caApp.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("SELECT set_config('app.tenant_id', ?, true)", tenantA).Error; err != nil {
				return err
			}
			var visible int64
			tx.Raw("SELECT count(*) FROM ca_certificates").Scan(&visible)
			if visible != 1 {
				t.Errorf("con app.tenant_id = A se ven %d filas, se esperaba 1", visible)
			}
			res := tx.Exec("UPDATE ca_certificates SET tenant_id = ? WHERE tenant_id = ?", tenantA, tenantB)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 0 {
				t.Errorf("UPDATE entre tenants modificó %d filas", res.RowsAffected)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		var stillB int64
		caAdmin.Raw("SELECT count(*) FROM ca_certificates WHERE id = 'ca-b' AND tenant_id = ?", tenantB).Scan(&stillB)
		if stillB != 1 {
			t.Error("la fila de B cambió de tenant")
		}
	})

	t.Run("PrepareIsIdempotentAndRotatesPassword", func(t *testing.T) {
		again, err := Prepare(context.Background(), logger, admin)
		if err != nil {
			t.Fatalf("segundo Prepare: %v", err)
		}
		second := appConfig(t, again)
		if second.Password == app.Password {
			t.Error("la contraseña de lamassu_app no se regeneró")
		}
		db := mustOpen(t, second, "controlplane")
		var n int64
		if err := db.Raw("SELECT count(*) FROM tenants").Scan(&n).Error; err != nil {
			t.Errorf("lamassu_app no puede leer controlplane con la nueva contraseña: %v", err)
		}
	})

	// Una tabla o secuencia sin permisos para lamassu_app es un hueco de las
	// migraciones que el chart también tendría: Prepare falla y no lo tapa.
	t.Run("MissingGrantFailsInsteadOfBeingGranted", func(t *testing.T) {
		if err := caAdmin.Exec("CREATE TABLE public.forgotten_table (id int); CREATE SEQUENCE public.forgotten_seq").Error; err != nil {
			t.Fatal(err)
		}
		_, err := Prepare(context.Background(), logger, admin)
		if err == nil {
			t.Fatal("Prepare no falla con una tabla sin permisos para lamassu_app")
		}
		for _, hint := range []string{"ca", "forgotten_table", "forgotten_seq", "migration"} {
			if !strings.Contains(err.Error(), hint) {
				t.Errorf("el error %q no nombra %q", err, hint)
			}
		}
		var granted bool
		caAdmin.Raw("SELECT has_table_privilege(?, 'public.forgotten_table', 'SELECT')", AppRole).Scan(&granted)
		if granted {
			t.Error("Prepare concedió permisos que las migraciones no dan")
		}
	})
}

func TestPrepareRejectsPrivilegedLamassuApp(t *testing.T) {
	admin := runBarePostgres(t)
	adminPG := mustOpen(t, admin, "postgres")
	if err := adminPG.Exec("CREATE ROLE lamassu_app LOGIN BYPASSRLS").Error; err != nil {
		t.Fatal(err)
	}

	_, err := Prepare(context.Background(), chelpers.SetupLogger(cconfig.Info, "test", "devstorage"), admin)
	if err == nil || !strings.Contains(err.Error(), "NOBYPASSRLS") {
		t.Fatalf("Prepare con lamassu_app BYPASSRLS: error %v, se esperaba uno que exija NOBYPASSRLS", err)
	}
}
