// Package devstorage prepara el PostgreSQL del monolito de desarrollo como en
// el despliegue con Helm (spec 009, D2): el usuario administrativo crea las
// bases y migra; los servicios usan el rol lamassu_app (NOSUPERUSER,
// NOBYPASSRLS), así que RLS se aplica también en local.
package devstorage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	pgconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// AppRole es el rol sin privilegios de los servicios. Lo crean las
// migraciones (*_enable_tenant_rls.sql y controlplane/*_grant_lamassu_app.sql).
const AppRole = "lamassu_app"

// Databases son las bases del perfil multitenant, incluida controlplane.
var Databases = []string{
	postgres.CA_DB_NAME,
	postgres.ALERTS_DB_NAME,
	postgres.DMS_DB_NAME,
	postgres.DEVICE_DB_NAME,
	postgres.VA_DB_NAME,
	postgres.KMS_DB_NAME,
	postgres.CONTROLPLANE_DB_NAME,
}

// Result es la configuración de almacenamiento de los servicios (con
// lamassu_app) y los GRANT que Prepare tuvo que añadir a los de las
// migraciones. Con las migraciones actuales Grants queda vacío; si no lo
// está, el chart tiene el mismo hueco y hay que corregir la migración.
type Result struct {
	Storage cconfig.PluggableStorageEngine
	Grants  []string
}

// Prepare crea las bases que falten, las migra como administrador, fija una
// contraseña aleatoria a lamassu_app y comprueba sus permisos. Es idempotente:
// sirve para un PostgreSQL en Docker o para uno externo ya preparado.
func Prepare(ctx context.Context, logger *logrus.Entry, admin pgconfig.PostgresPSEConfig) (*Result, error) {
	if admin.Hostname == "" || admin.Username == "" {
		return nil, errors.New("postgres admin hostname and username are required")
	}

	adminDB, closeAdmin, err := connect(logger, admin, "postgres")
	if err != nil {
		return nil, fmt.Errorf("could not connect to postgres as %s: %w", admin.Username, err)
	}
	defer closeAdmin()

	for _, name := range Databases {
		if err := createDatabaseIfMissing(adminDB, name); err != nil {
			return nil, err
		}
		if err := migrate(ctx, logger, admin, name); err != nil {
			return nil, err
		}
	}

	if err := checkAppRole(adminDB); err != nil {
		return nil, err
	}

	password, err := randomPassword()
	if err != nil {
		return nil, err
	}
	// La contraseña es hexadecimal: no necesita escape.
	if err := adminDB.Exec(fmt.Sprintf("ALTER ROLE %s WITH LOGIN PASSWORD '%s'", AppRole, password)).Error; err != nil {
		return nil, fmt.Errorf("could not set %s password: %w", AppRole, err)
	}

	var grants []string
	for _, name := range Databases {
		applied, err := grantMissing(logger, admin, name)
		if err != nil {
			return nil, err
		}
		grants = append(grants, applied...)
	}

	storageConfig, err := cconfig.EncodeStruct(pgconfig.PostgresPSEConfig{
		Hostname:     admin.Hostname,
		Port:         admin.Port,
		Username:     AppRole,
		Password:     cconfig.Password(password),
		MaxOpenConns: admin.MaxOpenConns,
	})
	if err != nil {
		return nil, fmt.Errorf("could not encode service storage config: %w", err)
	}

	return &Result{
		Storage: cconfig.PluggableStorageEngine{
			LogLevel: cconfig.Info,
			Provider: cconfig.Postgres,
			Config:   storageConfig,
		},
		Grants: grants,
	}, nil
}

func connect(logger *logrus.Entry, cfg pgconfig.PostgresPSEConfig, database string) (*gorm.DB, func(), error) {
	db, err := postgres.CreatePostgresDBConnection(logger, cfg, database)
	if err != nil {
		return nil, nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, nil, err
	}
	return db, func() { _ = sqlDB.Close() }, nil
}

func createDatabaseIfMissing(adminDB *gorm.DB, name string) error {
	var exists int64
	if err := adminDB.Raw("SELECT count(*) FROM pg_database WHERE datname = ?", name).Scan(&exists).Error; err != nil {
		return fmt.Errorf("could not check database %s: %w", name, err)
	}
	if exists > 0 {
		return nil
	}
	// Los nombres son constantes del paquete postgres, no entrada de usuario.
	if err := adminDB.Exec(fmt.Sprintf("CREATE DATABASE %q", name)).Error; err != nil {
		return fmt.Errorf("could not create database %s: %w", name, err)
	}
	return nil
}

func migrate(ctx context.Context, logger *logrus.Entry, admin pgconfig.PostgresPSEConfig, name string) error {
	db, closeDB, err := connect(logger, admin, name)
	if err != nil {
		return fmt.Errorf("could not connect to database %s: %w", name, err)
	}
	defer closeDB()

	if _, err := postgres.NewMigrator(logger, db).Goose.Up(ctx); err != nil {
		return fmt.Errorf("could not migrate database %s: %w", name, err)
	}
	return nil
}

func checkAppRole(adminDB *gorm.DB) error {
	var roles []struct {
		RolSuper     bool `gorm:"column:rolsuper"`
		RolBypassRLS bool `gorm:"column:rolbypassrls"`
	}
	if err := adminDB.Raw("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = ?", AppRole).Scan(&roles).Error; err != nil {
		return fmt.Errorf("could not read role %s: %w", AppRole, err)
	}
	if len(roles) == 0 {
		return fmt.Errorf("role %s does not exist after migrations", AppRole)
	}
	if roles[0].RolSuper || roles[0].RolBypassRLS {
		return fmt.Errorf("role %s must be NOSUPERUSER and NOBYPASSRLS so row level security applies (rolsuper=%v, rolbypassrls=%v)",
			AppRole, roles[0].RolSuper, roles[0].RolBypassRLS)
	}
	return nil
}

// grantMissing concede a lamassu_app el DML de las tablas y el uso de las
// secuencias que las migraciones no le hayan dado, y devuelve lo aplicado.
func grantMissing(logger *logrus.Entry, admin pgconfig.PostgresPSEConfig, name string) ([]string, error) {
	db, closeDB, err := connect(logger, admin, name)
	if err != nil {
		return nil, fmt.Errorf("could not connect to database %s: %w", name, err)
	}
	defer closeDB()

	var tables []string
	if err := db.Raw(`SELECT quote_ident(c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname <> 'goose_db_version'
		AND NOT has_table_privilege(?, c.oid, 'SELECT,INSERT,UPDATE,DELETE')
		ORDER BY c.relname`, AppRole).Scan(&tables).Error; err != nil {
		return nil, fmt.Errorf("could not check %s table privileges in %s: %w", AppRole, name, err)
	}

	var sequences []string
	if err := db.Raw(`SELECT quote_ident(c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'S' AND c.relname <> 'goose_db_version_id_seq'
		-- CASE: PostgreSQL no garantiza el orden del WHERE y has_sequence_privilege falla con una tabla.
		AND CASE WHEN c.relkind = 'S' THEN NOT has_sequence_privilege(?, c.oid, 'USAGE,SELECT') ELSE false END
		ORDER BY c.relname`, AppRole).Scan(&sequences).Error; err != nil {
		return nil, fmt.Errorf("could not check %s sequence privileges in %s: %w", AppRole, name, err)
	}

	var applied []string
	for _, table := range tables {
		stmt := fmt.Sprintf("GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%s TO %s", table, AppRole)
		if err := db.Exec(stmt).Error; err != nil {
			return nil, fmt.Errorf("%s: %s: %w", name, stmt, err)
		}
		applied = append(applied, name+": "+stmt)
	}
	for _, sequence := range sequences {
		stmt := fmt.Sprintf("GRANT USAGE, SELECT ON SEQUENCE public.%s TO %s", sequence, AppRole)
		if err := db.Exec(stmt).Error; err != nil {
			return nil, fmt.Errorf("%s: %s: %w", name, stmt, err)
		}
		applied = append(applied, name+": "+stmt)
	}
	for _, stmt := range applied {
		logger.Warnf("grant not provided by migrations, applied by the monolith: %s", stmt)
	}
	return applied, nil
}

func randomPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("could not generate %s password: %w", AppRole, err)
	}
	return hex.EncodeToString(buf), nil
}
