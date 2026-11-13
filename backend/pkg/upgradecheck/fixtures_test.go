package upgradecheck

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	lconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// fixture writes 3.8 rows into the ca, kms and va schemas of a runV38DB database.
type fixture struct {
	t   *testing.T
	cfg *lconfig.PostgresPSEConfig
	env *Env
	db  *gorm.DB
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	cfg := runV38DB(t)
	env := NewEnv(testLogger, *cfg)
	db, err := env.Schema("va")
	require.NoError(t, err)
	return &fixture{t: t, cfg: cfg, env: env, db: db}
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	require.NoError(f.t, f.db.Exec(sql, args...).Error)
}

// cert inserts a self-signed CA certificate with a fresh key and returns its SKI (hex). With an engine id the key is
// also registered in the KMS, named after the SHA-256 of its SubjectPublicKeyInfo, as the v4 CA migrations expect.
func (f *fixture) cert(serial, engineID string) string {
	f.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f.t, err)
	skiBytes := make([]byte, 20)
	_, err = rand.Read(skiBytes)
	require.NoError(f.t, err)
	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(f.t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: serial},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          skiBytes,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(f.t, err)
	certB64 := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	ski := hex.EncodeToString(skiBytes)

	f.rawCert(serial, ski, engineID, certB64)
	if engineID != "" {
		spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		require.NoError(f.t, err)
		digest := sha256.Sum256(spki)
		pub := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
		f.exec(`INSERT INTO kms.kms_keys (key_id, engine_id, name, algorithm, size, public_key, has_private_key, creation_ts)
			VALUES (?, ?, ?, 'ECDSA', 256, ?, true, now())`, hex.EncodeToString(digest[:]), engineID, serial, pub)
	}
	return ski
}

// rawCert inserts a certificate row as is, e.g. one whose certificate column does not decode.
func (f *fixture) rawCert(serial, ski, engineID, certificate string) {
	f.t.Helper()
	f.exec(`INSERT INTO ca.certificates (serial_number, certificate, subject_key_id, engine_id, type, status, is_ca,
			subject_common_name, valid_from, valid_to, metadata)
		VALUES (?, ?, ?, ?, 'MANAGED', 'ACTIVE', true, ?, now() - interval '1 hour', now() + interval '1 day', '{}')`,
		serial, certificate, ski, engineID, serial)
}

// rawCertLike inserts a copy of the certificate row of another serial: two CAs on the same key.
func (f *fixture) rawCertLike(serial, from string) {
	f.t.Helper()
	f.exec(`INSERT INTO ca.certificates (serial_number, certificate, subject_key_id, engine_id, type, status, is_ca,
			subject_common_name, valid_from, valid_to, metadata)
		SELECT ?, certificate, subject_key_id, engine_id, type, status, is_ca, ?, valid_from, valid_to, metadata
		FROM ca.certificates WHERE serial_number = ?`, serial, serial, from)
}

func (f *fixture) ca(id, serial, creation string) {
	f.t.Helper()
	f.exec(`INSERT INTO ca.ca_certificates (id, serial_number, creation_ts, level, metadata) VALUES (?, ?, ?, 0, '{}')`,
		id, serial, creation)
}

func (f *fixture) role(caSKI, signerSKI string) {
	f.t.Helper()
	f.exec(`INSERT INTO va.va_role (ca_ski, crl_subject_key_id_signer, crl_validity, crl_refresh_interval,
			crl_regenerate_on_revoke, latest_crl_version, latest_crl_valid_from, latest_crl_valid_until)
		VALUES (?, ?, '168h0m0s', '166h0m0s', true, 3, now(), now() + interval '7 days')`, caSKI, signerSKI)
}

// problemsByCheck runs the checks and keys their problems by check name. It fails the test if a check errors.
func problemsByCheck(t *testing.T, results []Result) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, r := range results {
		require.NoError(t, r.Err, "check %s", r.Check.Name)
		if len(r.Problems) > 0 {
			out[r.Check.Name] = r.Problems
		}
	}
	return out
}
