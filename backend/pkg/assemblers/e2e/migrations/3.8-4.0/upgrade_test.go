package migrations38to40

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/migration/catokms"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

// TestUpgrade38To40 upgrades a 3.8.1 database to v4 with the real migrations and the real ca-to-kms-migration tool. It
// checks the KMS rows the upgrade leaves (RFC-008, docs/internal-specs/rfc-008-kms-key-identity.md), then uses the
// PKI.
//
// The 3.8.x tool registered every CA key under the CA's SKI and looked it up only by that name. A CA imported with
// its key since 3.7 is already stored under the digest of its public key, so for any CA whose SKI is not that digest
// (any OpenSSL certificate) the tool added a second row that no engine object backs.
//
// The CAs (testdata/gen.sh):
//
//	A  OpenSSL SKI (SHA-1 of the key)  imported with its key in 3.8: row and engine file named by its digest
//	B  SKI "patata"                    from before the KMS: engine file named by its SKI, no KMS row
//	C  SKI = digest                    created by Lamassu 3.8: row, file and SKI all named by its digest
//	D  OpenSSL SKI                     imported with its key on v4
//	E  SKI "patata2"                   imported with its key on v4
//	F  SKI = digest                    created by Lamassu v4
//
// Two variants: "clean", and "ghost-from-3.8-tool", where the 3.8.x tool already ran and left a ghost row for A.
// They run one after the other, because postgres.NewMigrator resets goose's process-wide registry.
//
//  1. 3.8 state, written with SQL: A, B and C with their va_role and the last CRL 3.8 published, and the key files.
//  2. Upgrade in the production order ca-to-kms-migration -> kms -> ca -> va. Right after it, kms_keys holds exactly
//     A, B and C, with no ghost, and every row has its engine file and every file its row. B is still named by its
//     SKI, and certificates and CRL signers reference the rows.
//  3. The KMS starts with migrate_keys_format. B is renamed to its digest in the engine and in its row, keeps its id,
//     and keeps its SKI as an alias, and the foreign keys carry the new name to ca and va. The 3.8 CRLs are still
//     served at /crl/<SKI> and /crl/<CA id>.
//  4. D, E and F are added on v4 and stored under their digest. Keys resolve by id, digest, PKCS#11 URI and alias,
//     never by an OpenSSL SKI. Running the rename and the tool again changes nothing.
//  5. Each root signs two levels of subordinate CAs and a leaf. Revocations reach the CRL at the CDP of each revoked
//     certificate, signed by its issuer. /crl/<SKI> serves the CRL of A, B and C and answers 404 for D, E and F.
func TestUpgrade38To40(t *testing.T) {
	for _, v := range []variant{variantClean, variantGhost} {
		t.Run(string(v), func(t *testing.T) {
			e := newEnv(t, v)
			a, b, c := e.fx["A"], e.fx["B"], e.fx["C"]

			// Phase 1: the 3.8 state.
			e.write38State()
			require.Equal(t, map[variant]int{variantClean: 2, variantGhost: 4}[v], e.kmsRowCount(), "kms_keys rows in 3.8")
			require.Equal(t, sortedStrings(a.Digest, skiB, c.Digest), e.engineFiles(), "engine files in 3.8")

			// Phase 2: the upgrade, in the production order ca-to-kms-migration -> kms -> ca -> va.
			res := e.runTool()
			e.migrate(postgres.KMS_SCHEMA)
			e.migrate(postgres.CA_SCHEMA)
			e.migrate(postgres.VA_SCHEMA)
			require.Equal(t, map[variant]catokms.Result{
				variantClean: {Inserted: 1, Skipped: 2}, // B inserted; A found by its public key, C by its key_id
				variantGhost: {Skipped: 3},              // B and the ghost of A found by their SKI: the kms migration then removes the ghost
			}[v], res)

			// Moment 1: right after the migrations.
			m1 := e.kmsRows()
			require.Len(t, m1, 3, "kms_keys rows at moment 1: A, B and C, no ghost")
			aliasesA := []string{}
			if v == variantGhost {
				aliasesA = []string{a.SKI} // the kms migration keeps the name of the removed ghost as an alias
			}
			e.requireKey(m1, a, a.Digest, aliasesA)
			e.requireKey(m1, b, skiB, []string{})
			e.requireKey(m1, c, c.Digest, []string{})
			requireDistinctUUIDs(t, m1)
			require.Equal(t, keyIDs(m1), e.engineFiles(), "every row has its key in the engine and every key its row")
			require.Equal(t, a.Digest, e.certKeyID("A"))
			require.Equal(t, skiB, e.certKeyID("B"), "relinked by public key to the name the KMS holds it under")
			require.Equal(t, c.Digest, e.certKeyID("C"))
			e.requireCRLSigner("A", a.Digest, a.SKI)
			e.requireCRLSigner("B", skiB, skiB)
			e.requireCRLSigner("C", c.Digest, c.Digest)

			// Phase 3: the services start, and the KMS renames the keys whose name is not their digest
			// (crypto_engines.migrate_keys_format).
			srv := e.startServices()

			// Moment 2.
			m2 := e.kmsRows()
			require.Len(t, m2, 3, "kms_keys rows at moment 2")
			for digest, row := range m1 {
				require.Equal(t, row.ID, m2[digest].ID, "the id of key %s survives the rename", row.KeyID)
			}
			e.requireKey(m2, a, a.Digest, aliasesA)
			e.requireKey(m2, b, b.Digest, []string{skiB})
			e.requireKey(m2, c, c.Digest, []string{})
			require.Equal(t, sortedStrings(a.Digest, b.Digest, c.Digest), e.engineFiles(), "B renamed in the engine")
			require.Equal(t, a.Digest, e.certKeyID("A"))
			require.Equal(t, b.Digest, e.certKeyID("B"), "the certificate follows the rename (ON UPDATE CASCADE)")
			require.Equal(t, c.Digest, e.certKeyID("C"))
			e.requireCRLSigner("A", a.Digest, a.SKI)
			e.requireCRLSigner("B", b.Digest, skiB)
			e.requireCRLSigner("C", c.Digest, c.Digest)
			// The last CRL 3.8 published is still downloadable, at the URL 3.8 wrote in the CDPs (/crl/<SKI>) and at
			// the one v4 writes (/crl/<CA id>).
			for _, fx := range []fixtureCA{a, b, c} {
				bySKI := downloadCRL(t, srv, fx.SKI, fx.Cert)
				byID := downloadCRL(t, srv, e.caID[fx.Name], fx.Cert)
				require.Equal(t, e.crl38[fx.Name].Raw, bySKI.Raw, "CRL of %s published by 3.8, at /crl/<SKI>", fx.Name)
				require.Equal(t, e.crl38[fx.Name].Raw, byID.Raw, "CRL of %s published by 3.8, at /crl/<CA id>", fx.Name)
			}

			// Phase 4: CAs added on v4, before any issuance so that the counts cover the roots only.
			ctx := context.Background()
			dfx, efx := e.fx["D"], e.fx["E"]
			profile := newProfile(t, srv)
			dCA, eCA := e.importCA(srv, "D", profile), e.importCA(srv, "E", profile)
			f := e.createRootF(srv, profile)
			require.Equal(t, dfx.Digest, dCA.Certificate.KeyID)
			require.Equal(t, efx.Digest, eCA.Certificate.KeyID)
			fCert := (*x509.Certificate)(f.Certificate.Certificate)
			fDigest, err := chelpers.PublicKeyDigest(fCert.PublicKey)
			require.NoError(t, err)
			require.Equal(t, fDigest, f.Certificate.KeyID)
			require.Equal(t, fDigest, hex.EncodeToString(fCert.SubjectKeyId), "the SKI Lamassu writes is the digest of the key")

			m4 := e.kmsRows()
			require.Len(t, m4, 6, "kms_keys rows after the v4 CAs")
			for digest, row := range m2 {
				require.Equal(t, row, m4[digest], "key %s is untouched", row.KeyID)
			}
			e.requireKey(m4, dfx, dfx.Digest, []string{})
			e.requireKey(m4, efx, efx.Digest, []string{})
			e.requireKey(m4, fixtureCA{Name: "F", Digest: fDigest}, fDigest, []string{})
			for _, row := range m4 {
				require.Equal(t, row.Digest, row.KeyID, "every key is named by its digest")
			}
			requireDistinctUUIDs(t, m4)

			// Resolution of identifiers (RFC-008 5.2).
			resolve := func(identifier string) (*models.Key, error) {
				return srv.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: identifier})
			}
			requireResolves := func(identifier, digest string) {
				t.Helper()
				key, err := resolve(identifier)
				require.NoError(t, err, "resolve %s", identifier)
				require.Equal(t, digest, key.Digest, "resolve %s", identifier)
			}
			requireNotFound := func(identifier string) {
				t.Helper()
				_, err := resolve(identifier)
				require.ErrorIs(t, err, errs.ErrKeyNotFound, "resolve %s", identifier)
			}
			for _, row := range m4 {
				requireResolves(row.ID, row.Digest)
				requireResolves(row.Digest, row.Digest)
				requireResolves(keyURI(row.KeyID), row.Digest)
			}
			requireResolves(skiB, b.Digest)  // the alias the rename left
			requireResolves(c.SKI, c.Digest) // a Lamassu SKI is the digest
			requireResolves(hex.EncodeToString(fCert.SubjectKeyId), fDigest)
			if v == variantGhost {
				requireResolves(a.SKI, a.Digest) // the alias the kms migration kept from the ghost
			} else {
				requireNotFound(a.SKI)
			}
			requireNotFound(dfx.SKI) // an SKI is not an identifier
			requireNotFound(skiE)

			// Running the upgrade steps again changes nothing.
			renamed, err := assemblers.NormalizeKMSKeyNames(ctx, e.kmsConfig())
			require.NoError(t, err)
			require.Zero(t, renamed)
			require.Equal(t, catokms.Result{Skipped: 6}, e.runTool())
			require.Equal(t, m4, e.kmsRows())

			// Phase 5: every root issues through two levels of subordinate CAs, and revocations reach CRLs signed by
			// the right key.
			for _, name := range []string{"A", "B", "C", "D", "E", "F"} {
				t.Run("battery "+name, func(t *testing.T) { e.issuanceBattery(t, srv, name, profile) })
			}
			m5 := e.kmsRows()
			require.Len(t, m5, 18, "kms_keys rows: 6 roots and 12 subordinate keys")
			for digest, row := range m4 {
				require.Equal(t, row, m5[digest], "key %s is untouched by the issuance", row.KeyID)
			}
			for _, row := range m5 {
				require.Equal(t, row.Digest, row.KeyID, "every key is named by its digest")
			}
			renamed, err = assemblers.NormalizeKMSKeyNames(ctx, e.kmsConfig())
			require.NoError(t, err)
			require.Zero(t, renamed)
			require.Equal(t, catokms.Result{Skipped: 18}, e.runTool(), "the tool reads subordinate and revoked CAs too")
		})
	}
}
