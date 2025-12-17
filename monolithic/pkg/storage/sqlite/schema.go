package sqlite

import (
	"gorm.io/gorm"
)

// initializeSchema creates all tables in their final state based on the Postgres schema
// This bypasses migrations and creates tables directly in SQLite-compatible SQL
// Schema reflects the final state after all Postgres migrations are applied
func initializeSchema(db *gorm.DB) error {
	statements := []string{
		// CA Certificates table - Final state after migrations:
		// - 20241215165048_add_key_id.sql: Added key_id column (later dropped)
		// - 20241223183344_unified_ca_models.sql: Dropped most columns, added validity_type/time/duration
		// - 20250908074250_add_profile_id.go: Added profile_id column
		`CREATE TABLE IF NOT EXISTS ca_certificates (
			serial_number TEXT NOT NULL,
			metadata TEXT NULL,
			id TEXT NOT NULL,
			creation_ts DATETIME NULL,
			level INTEGER NULL,
			validity_type TEXT NULL,
			validity_time DATETIME NULL,
			validity_duration TEXT NULL,
			profile_id TEXT NULL,
			PRIMARY KEY (serial_number, id),
			FOREIGN KEY (serial_number) REFERENCES certificates (serial_number) ON DELETE CASCADE
		)`,

		// Certificates table - Final state after migrations:
		// - 20241215165048_add_key_id.sql: Added key_id column (later renamed to subject_key_id)
		// - 20241223183344_unified_ca_models.sql: Renamed key_strength_meta_* to key_meta_*, changed types
		// - 20250107164937_add_is_ca.sql: Added is_ca column
		// - 20250226114600_ca_add_kids.go: Renamed key_id to subject_key_id, added authority_key_id and issuer_* columns
		// - 20250704101200_add_version_schema.sql: Added version_schema column
		`CREATE TABLE IF NOT EXISTS certificates (
			serial_number TEXT NOT NULL,
			metadata TEXT NULL,
			issuer_meta_serial_number TEXT NULL,
			issuer_meta_id TEXT NULL,
			issuer_meta_level INTEGER NULL,
			status TEXT NULL,
			certificate TEXT NULL,
			key_meta_type TEXT NULL,
			key_meta_bits INTEGER NULL,
			key_meta_strength TEXT NULL,
			subject_common_name TEXT NULL,
			subject_organization TEXT NULL,
			subject_organization_unit TEXT NULL,
			subject_country TEXT NULL,
			subject_state TEXT NULL,
			subject_locality TEXT NULL,
			valid_from DATETIME NULL,
			valid_to DATETIME NULL,
			revocation_timestamp DATETIME NULL,
			revocation_reason TEXT NULL,
			type TEXT NULL,
			engine_id TEXT NULL,
			subject_key_id TEXT NULL,
			authority_key_id TEXT NULL,
			issuer_common_name TEXT NULL,
			issuer_organization TEXT NULL,
			issuer_organization_unit TEXT NULL,
			issuer_country TEXT NULL,
			issuer_state TEXT NULL,
			issuer_locality TEXT NULL,
			is_ca INTEGER NULL,
			version_schema TEXT NULL,
			PRIMARY KEY (serial_number)
		)`,

		// Issuance Profiles table - Final state after creation (no subsequent migrations)
		// - 20250702124800_create_issuance_profile.sql: Initial creation
		`CREATE TABLE IF NOT EXISTS issuance_profiles (
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			validity_type TEXT NOT NULL,
			validity_time DATETIME NULL,
			validity_duration TEXT NULL,
			sign_as_ca INTEGER NOT NULL DEFAULT 0,
			honor_key_usage INTEGER NOT NULL DEFAULT 1,
			key_usage TEXT NOT NULL DEFAULT '{}',
			honor_extended_key_usages INTEGER NOT NULL DEFAULT 1,
			extended_key_usages TEXT NOT NULL DEFAULT '{}',
			honor_subject INTEGER NOT NULL DEFAULT 1,
			subject_common_name TEXT NOT NULL DEFAULT '',
			subject_organization TEXT DEFAULT '',
			subject_organization_unit TEXT DEFAULT '',
			subject_country TEXT DEFAULT '',
			subject_state TEXT DEFAULT '',
			subject_locality TEXT DEFAULT '',
			honor_extensions INTEGER NOT NULL DEFAULT 1,
			crypto_enforcement_enabled INTEGER NOT NULL DEFAULT 0,
			crypto_enforcement_allow_rsa_keys INTEGER NOT NULL DEFAULT 1,
			crypto_enforcement_allowed_rsa_key_sizes TEXT DEFAULT '{}',
			crypto_enforcement_allow_ecdsa_keys INTEGER NOT NULL DEFAULT 1,
			crypto_enforcement_allowed_ecdsa_key_sizes TEXT DEFAULT '{}',
			PRIMARY KEY (id)
		)`,

		// Devices table - Final state (no migrations)
		`CREATE TABLE IF NOT EXISTS devices (
			id TEXT NOT NULL,
			tags TEXT NULL,
			status TEXT NULL,
			icon TEXT NULL,
			icon_color TEXT NULL,
			creation_timestamp DATETIME NULL,
			metadata TEXT NULL,
			dms_owner TEXT NULL,
			identity_slot TEXT NULL,
			extra_slots TEXT NULL,
			events TEXT NULL,
			PRIMARY KEY (id)
		)`,

		// DMS table - Final state (no migrations)
		`CREATE TABLE IF NOT EXISTS dms (
			id TEXT NOT NULL,
			name TEXT NULL,
			metadata TEXT NULL,
			creation_date DATETIME NULL,
			settings TEXT NULL,
			PRIMARY KEY (id)
		)`,

		// VA Role table - Final state (no migrations)
		// Note: latest_crl_version uses TEXT because BigInt type has serializer:text tag
		`CREATE TABLE IF NOT EXISTS va_role (
			ca_ski TEXT NOT NULL,
			crl_refresh_interval TEXT,
			crl_validity TEXT,
			crl_subject_key_id_signer TEXT,
			crl_regenerate_on_revoke INTEGER,
			latest_crl_version TEXT,
			latest_crl_valid_from DATETIME,
			latest_crl_valid_until DATETIME,
			PRIMARY KEY (ca_ski)
		)`,

		// Events table - Final state (no migrations)
		`CREATE TABLE IF NOT EXISTS events (
			event_type TEXT NOT NULL,
			event TEXT NULL,
			last_seen DATETIME NULL,
			total_seen INTEGER NULL,
			PRIMARY KEY (event_type)
		)`,

		// Subscriptions table - Final state (no migrations)
		`CREATE TABLE IF NOT EXISTS subscriptions (
			id TEXT NOT NULL,
			user_id TEXT NULL,
			event_type TEXT NULL,
			subscription_date DATETIME NULL,
			conditions TEXT NULL,
			channel TEXT NULL,
			PRIMARY KEY (id)
		)`,

		// KMS Keys table - Final state after migrations:
		// - 20251031174938_key.sql: Added engine_id, key_id, aliases, has_private_key, tags;
		//                           changed primary key from id to key_id; dropped status column;
		//                           changed metadata to jsonb
		`CREATE TABLE IF NOT EXISTS kms_keys (
			key_id TEXT NOT NULL,
			metadata TEXT NULL,
			name TEXT NOT NULL,
			algorithm TEXT NOT NULL,
			size INTEGER NOT NULL,
			public_key TEXT NOT NULL,
			creation_ts DATETIME NULL,
			engine_id TEXT NULL,
			aliases TEXT DEFAULT '[]',
			has_private_key INTEGER DEFAULT 1,
			tags TEXT DEFAULT '[]',
			PRIMARY KEY (key_id)
		)`,
	}

	for _, stmt := range statements {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}

	return nil
}
