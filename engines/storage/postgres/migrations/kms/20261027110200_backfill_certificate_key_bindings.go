package kms

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	mhelper "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20261027110200BackfillCertificateKeyBindings() {
	goose.AddMigrationContext(upBackfillCertificateKeyBindings, downBackfillCertificateKeyBindings)
}

// upBackfillCertificateKeyBindings makes the certificate bindings match the certificates that use each
// key: the certificates of each CA, its current one and the ones it reissued (deleted CAs leave their
// certificates behind), and every other certificate whose key the KMS holds, whatever its status.
// Earlier versions only bound some of them, in the key metadata, and never unbound them. The CA schema
// must be migrated first so that its certificates record their key_id.
//
// First it makes each certificate's key_id the name its key has in the KMS: the CA migration recorded
// the SHA-256 key ID, but crypto engines before the KMS renamed an imported CA's key to its
// certificate's SKI, and ca-to-kms-migration registered it under that name. Then it binds certificates
// by (key_id, engine_id). A binding whose certificate still exists with an unknown key_id (its
// certificate could not be read when key_id was backfilled) is kept: the key may still be in use.
func upBackfillCertificateKeyBindings(ctx context.Context, tx *sql.Tx) error {
	logger := chelpers.SetupLogger("info", "KMS", "Migrations")

	var hasCertificates bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('ca.certificates') IS NOT NULL AND to_regclass('ca.ca_certificates') IS NOT NULL`).Scan(&hasCertificates); err != nil {
		return err
	}
	if !hasCertificates {
		logger.Infof("no CA certificates found, no key bindings to backfill")
		return nil
	}

	var hasKeyID bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'ca' AND table_name = 'certificates' AND column_name = 'key_id')`).Scan(&hasKeyID); err != nil {
		return err
	}
	if !hasKeyID {
		return errors.New("ca.certificates has no key_id column: migrate the ca schema first, then the kms schema")
	}

	corrected, err := correctCertificateKeyIDs(ctx, tx, logger.Warnf)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		CREATE TEMP TABLE desired_certificate_bindings (key_id text, engine_id text, resource_id text) ON COMMIT DROP`); err != nil {
		return err
	}

	// The certificates of each CA: its current one and, following the reissued-from links back, the
	// ones it reissued with the same key. Like the CA when it deletes a CA, it only follows a link the
	// previous certificate returns with reissued-as: the links are metadata users can edit.
	if _, err := tx.ExecContext(ctx, `
		CREATE TEMP TABLE ca_certificate_history ON COMMIT DROP AS
		WITH RECURSIVE history (serial_number, key_id, engine_id, previous) AS (
			SELECT c.serial_number, c.key_id, c.engine_id, c.metadata ->> $1
			FROM ca.ca_certificates AS ca
			JOIN ca.certificates AS c ON c.serial_number = ca.serial_number
			UNION
			SELECT p.serial_number, p.key_id, p.engine_id, p.metadata ->> $1
			FROM history AS h
			JOIN ca.certificates AS p ON p.serial_number = h.previous AND p.key_id = h.key_id AND p.engine_id = h.engine_id
			WHERE p.metadata ->> $2 = h.serial_number
		)
		SELECT DISTINCT serial_number FROM history`, models.CAMetadataReissuedFromKey, models.CAMetadataReissuedAsKey); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO desired_certificate_bindings (key_id, engine_id, resource_id)
		SELECT c.key_id, c.engine_id, c.serial_number
		FROM ca.certificates AS c
		JOIN kms_keys AS k ON k.key_id = c.key_id AND k.engine_id = c.engine_id
		WHERE c.key_id <> '' AND c.engine_id <> ''
		  AND (c.is_ca = false OR EXISTS (SELECT 1 FROM ca_certificate_history AS h WHERE h.serial_number = c.serial_number))`); err != nil {
		return err
	}

	removed, err := tx.ExecContext(ctx, `
		DELETE FROM key_bindings AS b
		WHERE b.resource_type = 'certificate'
		  AND NOT EXISTS (SELECT 1 FROM desired_certificate_bindings AS d
		                  WHERE d.key_id = b.key_id AND d.engine_id = b.engine_id AND d.resource_id = b.resource_id)
		  AND NOT EXISTS (SELECT 1 FROM ca.certificates AS c WHERE c.serial_number = b.resource_id AND c.key_id = '')`)
	if err != nil {
		return err
	}

	added, err := tx.ExecContext(ctx, `
		INSERT INTO key_bindings (key_id, engine_id, resource_type, resource_id)
		SELECT key_id, engine_id, 'certificate', resource_id FROM desired_certificate_bindings
		ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}

	removedRows, _ := removed.RowsAffected()
	addedRows, _ := added.RowsAffected()
	logger.Infof("backfilled certificate key bindings: %d added, %d removed, %d key IDs corrected", addedRows, removedRows, corrected)
	return nil
}

// correctCertificateKeyIDs sets the key_id of the certificates whose key_id names no key in their engine
// to the key the engine holds with their public key, if any. Unreadable certificates are skipped.
func correctCertificateKeyIDs(ctx context.Context, tx *sql.Tx, warnf func(string, ...any)) (int, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT c.serial_number, c.engine_id, COALESCE(c.certificate, '')
		FROM ca.certificates AS c
		WHERE c.key_id <> '' AND c.engine_id <> ''
		  AND NOT EXISTS (SELECT 1 FROM kms_keys AS k WHERE k.key_id = c.key_id AND k.engine_id = c.engine_id)`)
	if err != nil {
		return 0, err
	}
	type unmatched struct{ serialNumber, engineID, certificate string }
	var certs []unmatched
	for rows.Next() {
		var u unmatched
		if err := rows.Scan(&u.serialNumber, &u.engineID, &u.certificate); err != nil {
			rows.Close()
			return 0, err
		}
		certs = append(certs, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	corrected := 0
	for _, u := range certs {
		cert, err := mhelper.DecodeCertificate(u.certificate)
		if err != nil {
			warnf("skipping certificate %s: could not decode it: %s", u.serialNumber, err)
			continue
		}
		spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			warnf("skipping certificate %s: unsupported public key: %s", u.serialNumber, err)
			continue
		}
		// The KMS stores public keys as the base64 of their PEM encoding.
		publicKey := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))

		res, err := tx.ExecContext(ctx, `
			UPDATE ca.certificates SET key_id = k.key_id
			FROM (SELECT key_id FROM kms_keys WHERE engine_id = $2 AND public_key = $3 ORDER BY key_id LIMIT 1) AS k
			WHERE serial_number = $1`, u.serialNumber, u.engineID, publicKey)
		if err != nil {
			return 0, fmt.Errorf("could not correct the key_id of certificate %s: %w", u.serialNumber, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			corrected++
		}
	}
	return corrected, nil
}

func downBackfillCertificateKeyBindings(ctx context.Context, tx *sql.Tx) error {
	// The bindings now match the certificates: there is nothing to undo.
	return nil
}
