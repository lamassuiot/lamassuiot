-- Run with psql, not through a migration framework:
--   export PGHOST=...
--   export PGPORT=5432
--   export PGUSER=...
--   export PGPASSWORD=...
--   psql -d postgres -f scripts/migrate-service-dbs-to-pki-schemas.sql
--
-- This script:
-- 1. Creates the pki, authz, and wfx databases if they do not exist.
-- 2. Creates the alerts, ca, va, devicemanager, dmsmanager, and kms schemas in pki.
-- 3. Copies each legacy <service>.public schema into pki.<service> using pg_dump + psql.
-- 4. Drops the legacy alerts, ca, va, devicemanager, dmsmanager, and kms databases.
--
-- Safety guard: the script aborts if any target schema in pki already contains objects.

\set ON_ERROR_STOP on

\connect postgres

SELECT format('CREATE DATABASE %I', db_name)
FROM (
		VALUES
				('pki'),
				('authz'),
				('wfx')
) AS wanted(db_name)
WHERE NOT EXISTS (
		SELECT 1
		FROM pg_database existing
		WHERE existing.datname = wanted.db_name
)
\gexec

\connect pki

CREATE SCHEMA IF NOT EXISTS alerts;
CREATE SCHEMA IF NOT EXISTS ca;
CREATE SCHEMA IF NOT EXISTS va;
CREATE SCHEMA IF NOT EXISTS devicemanager;
CREATE SCHEMA IF NOT EXISTS dmsmanager;
CREATE SCHEMA IF NOT EXISTS kms;

\echo Migrating alerts.public to pki.alerts
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname = 'alerts') THEN 1 ELSE 0 END AS alerts_exists \gset
\if :alerts_exists
SELECT CASE WHEN NOT EXISTS (
		SELECT 1
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'alerts'
			AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
) THEN 1 ELSE 0 END AS alerts_schema_empty \gset
\if :alerts_schema_empty
\! pg_dump --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=alerts --schema=public --no-owner --no-privileges --format=plain | sed -E -e '/^CREATE SCHEMA public;$/d' -e '/^ALTER SCHEMA public OWNER TO .*;$/d' -e '/^COMMENT ON SCHEMA public IS .*;$/d' -e 's/SET search_path = public, pg_catalog;/SET search_path = alerts, pg_catalog;/g' -e 's/"public"\./alerts./g' -e 's/\<public\./alerts./g' | psql --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=pki
\else
\echo Target schema pki.alerts is not empty. Aborting to avoid overwriting data.
\quit 1
\endif
\else
\echo Source database alerts does not exist. Skipping.
\endif

\echo Migrating ca.public to pki.ca
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname = 'ca') THEN 1 ELSE 0 END AS ca_exists \gset
\if :ca_exists
SELECT CASE WHEN NOT EXISTS (
		SELECT 1
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'ca'
			AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
) THEN 1 ELSE 0 END AS ca_schema_empty \gset
\if :ca_schema_empty
\! pg_dump --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=ca --schema=public --no-owner --no-privileges --format=plain | sed -E -e '/^CREATE SCHEMA public;$/d' -e '/^ALTER SCHEMA public OWNER TO .*;$/d' -e '/^COMMENT ON SCHEMA public IS .*;$/d' -e 's/SET search_path = public, pg_catalog;/SET search_path = ca, pg_catalog;/g' -e 's/"public"\./ca./g' -e 's/\<public\./ca./g' | psql --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=pki
\else
\echo Target schema pki.ca is not empty. Aborting to avoid overwriting data.
\quit 1
\endif
\else
\echo Source database ca does not exist. Skipping.
\endif

\echo Migrating va.public to pki.va
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname = 'va') THEN 1 ELSE 0 END AS va_exists \gset
\if :va_exists
SELECT CASE WHEN NOT EXISTS (
		SELECT 1
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'va'
			AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
) THEN 1 ELSE 0 END AS va_schema_empty \gset
\if :va_schema_empty
\! pg_dump --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=va --schema=public --no-owner --no-privileges --format=plain | sed -E -e '/^CREATE SCHEMA public;$/d' -e '/^ALTER SCHEMA public OWNER TO .*;$/d' -e '/^COMMENT ON SCHEMA public IS .*;$/d' -e 's/SET search_path = public, pg_catalog;/SET search_path = va, pg_catalog;/g' -e 's/"public"\./va./g' -e 's/\<public\./va./g' | psql --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=pki
\else
\echo Target schema pki.va is not empty. Aborting to avoid overwriting data.
\quit 1
\endif
\else
\echo Source database va does not exist. Skipping.
\endif

\echo Migrating devicemanager.public to pki.devicemanager
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname = 'devicemanager') THEN 1 ELSE 0 END AS devicemanager_exists \gset
\if :devicemanager_exists
SELECT CASE WHEN NOT EXISTS (
		SELECT 1
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'devicemanager'
			AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
) THEN 1 ELSE 0 END AS devicemanager_schema_empty \gset
\if :devicemanager_schema_empty
\! pg_dump --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=devicemanager --schema=public --no-owner --no-privileges --format=plain | sed -E -e '/^CREATE SCHEMA public;$/d' -e '/^ALTER SCHEMA public OWNER TO .*;$/d' -e '/^COMMENT ON SCHEMA public IS .*;$/d' -e 's/SET search_path = public, pg_catalog;/SET search_path = devicemanager, pg_catalog;/g' -e 's/"public"\./devicemanager./g' -e 's/\<public\./devicemanager./g' | psql --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=pki
\else
\echo Target schema pki.devicemanager is not empty. Aborting to avoid overwriting data.
\quit 1
\endif
\else
\echo Source database devicemanager does not exist. Skipping.
\endif

\echo Migrating dmsmanager.public to pki.dmsmanager
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname = 'dmsmanager') THEN 1 ELSE 0 END AS dmsmanager_exists \gset
\if :dmsmanager_exists
SELECT CASE WHEN NOT EXISTS (
		SELECT 1
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'dmsmanager'
			AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
) THEN 1 ELSE 0 END AS dmsmanager_schema_empty \gset
\if :dmsmanager_schema_empty
\! pg_dump --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=dmsmanager --schema=public --no-owner --no-privileges --format=plain | sed -E -e '/^CREATE SCHEMA public;$/d' -e '/^ALTER SCHEMA public OWNER TO .*;$/d' -e '/^COMMENT ON SCHEMA public IS .*;$/d' -e 's/SET search_path = public, pg_catalog;/SET search_path = dmsmanager, pg_catalog;/g' -e 's/"public"\./dmsmanager./g' -e 's/\<public\./dmsmanager./g' | psql --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=pki
\else
\echo Target schema pki.dmsmanager is not empty. Aborting to avoid overwriting data.
\quit 1
\endif
\else
\echo Source database dmsmanager does not exist. Skipping.
\endif

\echo Migrating kms.public to pki.kms
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname = 'kms') THEN 1 ELSE 0 END AS kms_exists \gset
\if :kms_exists
SELECT CASE WHEN NOT EXISTS (
		SELECT 1
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'kms'
			AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
) THEN 1 ELSE 0 END AS kms_schema_empty \gset
\if :kms_schema_empty
\! pg_dump --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=kms --schema=public --no-owner --no-privileges --format=plain | sed -E -e '/^CREATE SCHEMA public;$/d' -e '/^ALTER SCHEMA public OWNER TO .*;$/d' -e '/^COMMENT ON SCHEMA public IS .*;$/d' -e 's/SET search_path = public, pg_catalog;/SET search_path = kms, pg_catalog;/g' -e 's/"public"\./kms./g' -e 's/\<public\./kms./g' | psql --host="$PGHOST" --port="${PGPORT:-5432}" --username="$PGUSER" --dbname=pki
\else
\echo Target schema pki.kms is not empty. Aborting to avoid overwriting data.
\quit 1
\endif
\else
\echo Source database kms does not exist. Skipping.
\endif

\connect postgres

SELECT 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ''alerts'' AND pid <> pg_backend_pid();' \gexec
DROP DATABASE IF EXISTS alerts;

SELECT 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ''ca'' AND pid <> pg_backend_pid();' \gexec
DROP DATABASE IF EXISTS ca;

SELECT 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ''va'' AND pid <> pg_backend_pid();' \gexec
DROP DATABASE IF EXISTS va;

SELECT 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ''devicemanager'' AND pid <> pg_backend_pid();' \gexec
DROP DATABASE IF EXISTS devicemanager;

SELECT 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ''dmsmanager'' AND pid <> pg_backend_pid();' \gexec
DROP DATABASE IF EXISTS dmsmanager;

SELECT 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ''kms'' AND pid <> pg_backend_pid();' \gexec
DROP DATABASE IF EXISTS kms;
