package services

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"
	"gocloud.dev/blob/memblob"
)

// memCRLSettingsRepo is the in-memory CRLSettingsRepo with the semantics the service relies on.
type memCRLSettingsRepo struct {
	storage.CRLSettingsRepo
	mu       sync.Mutex
	rows     map[string]models.CRLSettings
	conflict bool // makes UpdateLatestCRL fail, as if another writer had won
}

type removeStagedAfterClaimRepo struct {
	*memCRLSettingsRepo
	bucket *blob.Bucket
}

func (r *removeStagedAfterClaimRepo) UpdateLatestCRL(ctx context.Context, id string, expected *big.Int, latest models.LatestCRLMeta) error {
	err := r.memCRLSettingsRepo.UpdateLatestCRL(ctx, id, expected, latest)
	if err == nil {
		files, _, listErr := r.bucket.ListPage(ctx, blob.FirstPageToken, 10, &blob.ListOptions{Prefix: crlObjectKey(id, latest.Version.String()) + "."})
		if listErr != nil {
			return listErr
		}
		for _, file := range files {
			if err := r.bucket.Delete(ctx, file.Key); err != nil {
				return err
			}
		}
	}
	return err
}

func newMemRepo(rows ...models.CRLSettings) *memCRLSettingsRepo {
	r := &memCRLSettingsRepo{rows: map[string]models.CRLSettings{}}
	for _, row := range rows {
		r.rows[row.CAID] = row
	}
	return r
}

func (r *memCRLSettingsRepo) Insert(_ context.Context, s *models.CRLSettings) (*models.CRLSettings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rows[s.CAID]; ok {
		return nil, fmt.Errorf("duplicate %s", s.CAID)
	}
	r.rows[s.CAID] = *s
	return s, nil
}

func (r *memCRLSettingsRepo) Get(_ context.Context, id string) (bool, *models.CRLSettings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.rows[id]
	if !ok {
		return false, nil, nil
	}
	return true, &s, nil
}

func (r *memCRLSettingsRepo) GetByLegacySKI(_ context.Context, ski string) (bool, *models.CRLSettings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.rows {
		if s.LegacySKI != nil && *s.LegacySKI == ski {
			return true, &s, nil
		}
	}
	return false, nil, nil
}

func (r *memCRLSettingsRepo) GetAll(_ context.Context, req storage.StorageListRequest[models.CRLSettings]) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.rows {
		req.ApplyFunc(s)
	}
	return "", nil
}

func (r *memCRLSettingsRepo) UpdateOptions(_ context.Context, id string, o models.CRLSettingsOptions) (*models.CRLSettings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.rows[id]
	if !ok {
		return nil, errs.ErrCRLSettingsNotFound
	}
	s.Options = o
	r.rows[id] = s
	return &s, nil
}

func (r *memCRLSettingsRepo) UpdateLatestCRL(_ context.Context, id string, expected *big.Int, latest models.LatestCRLMeta) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.rows[id]
	if r.conflict || s.LatestCRL.Version.Cmp(expected) != 0 {
		return errs.ErrCRLSettingsConflict
	}
	s.LatestCRL = latest
	r.rows[id] = s
	return nil
}

func (r *memCRLSettingsRepo) SetSigner(_ context.Context, id, expected, next string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.rows[id]
	if s.Options.SignerSerialNumber != expected {
		return false, nil
	}
	s.Options.SignerSerialNumber = next
	r.rows[id] = s
	return true, nil
}

// crlFixture is a software PKI: CAs, their certificates, revocations and a KMS that signs with the CA key.
type crlFixture struct {
	t        *testing.T
	repo     *memCRLSettingsRepo
	bucket   *blob.Bucket
	svc      *CRLServiceBackend
	key      *ecdsa.PrivateKey
	cas      map[string]models.CACertificate
	certs    map[string]models.Certificate
	revoked  map[string][]models.Certificate // by issuer CA id
	serialNo int64
}

type fakeCA struct {
	coreservices.CAService
	f *crlFixture
}

func (c fakeCA) GetCAByID(_ context.Context, in coreservices.GetCAByIDInput) (*models.CACertificate, error) {
	ca, ok := c.f.cas[in.CAID]
	if !ok {
		return nil, errs.ErrCANotFound
	}
	return &ca, nil
}

func (c fakeCA) GetCertificateBySerialNumber(_ context.Context, in coreservices.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	cert, ok := c.f.certs[in.SerialNumber]
	if !ok {
		return nil, errs.ErrCertificateNotFound
	}
	return &cert, nil
}

func (c fakeCA) GetCertificatesByCaAndStatus(_ context.Context, in coreservices.GetCertificatesByCaAndStatusInput) (string, error) {
	for _, cert := range c.f.revoked[in.CAID] {
		in.ApplyFunc(cert)
	}
	return "", nil
}

type fakeKMS struct {
	coreservices.KMSService
	f *crlFixture
}

func (k fakeKMS) GetKey(_ context.Context, in coreservices.GetKeyInput) (*models.Key, error) {
	der, _ := x509.MarshalPKIXPublicKey(&k.f.key.PublicKey)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &models.Key{KeyID: "key", EngineID: "engine", Algorithm: x509.ECDSA.String(), HasPrivateKey: true,
		PublicKey: base64.StdEncoding.EncodeToString(pemKey)}, nil
}

func (k fakeKMS) SignMessage(_ context.Context, in coreservices.SignMessageInput) (*models.MessageSignature, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, k.f.key, in.Message)
	return &models.MessageSignature{Signature: sig}, err
}

func newCRLFixture(t *testing.T, vaDomains ...string) *crlFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	if len(vaDomains) == 0 {
		vaDomains = []string{"va.example.com"}
	}
	f := &crlFixture{
		t: t, repo: newMemRepo(), bucket: memblob.OpenBucket(nil), key: key,
		cas: map[string]models.CACertificate{}, certs: map[string]models.Certificate{}, revoked: map[string][]models.Certificate{},
	}
	t.Cleanup(func() { _ = f.bucket.Close() })
	svc, err := NewCRLService(CRLServiceBuilder{
		VARepo: f.repo, Logger: logrus.NewEntry(logrus.New()), CAClient: fakeCA{f: f}, KMSClient: fakeKMS{f: f},
		Bucket: f.bucket, VADomains: vaDomains,
	})
	require.NoError(t, err)
	f.svc = svc.(*CRLServiceBackend)
	return f
}

func (f *crlFixture) newCert(cn string, keyUsage x509.KeyUsage, isCA bool, key *ecdsa.PrivateKey) models.Certificate {
	f.t.Helper()
	f.serialNo++
	ski := sha256.Sum256(elliptic.MarshalCompressed(key.Curve, key.X, key.Y))
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(f.serialNo), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: keyUsage, BasicConstraintsValid: true, IsCA: isCA, SubjectKeyId: ski[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, f.key)
	require.NoError(f.t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(f.t, err)
	x := models.X509Certificate(*parsed)
	cert := models.Certificate{
		SerialNumber: fmt.Sprintf("%02x", f.serialNo), SubjectKeyID: fmt.Sprintf("%x", ski), Certificate: &x,
		Status: models.StatusActive, EngineID: "engine", KeyID: "key",
	}
	f.certs[cert.SerialNumber] = cert
	return cert
}

// addCA registers a CA whose certificate is signed with the shared fixture key and has the given subject.
func (f *crlFixture) addCA(id, cn string) models.CACertificate {
	cert := f.newCert(cn, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true, f.key)
	ca := models.CACertificate{ID: id, Certificate: cert, CertificateSerialNumber: cert.SerialNumber, CreationTS: time.Now()}
	f.cas[id] = ca
	return ca
}

func (f *crlFixture) revoke(caID string, serial int64) {
	f.revoked[caID] = append(f.revoked[caID], models.Certificate{
		SerialNumber: fmt.Sprintf("%x", serial),
		Certificate:  &models.X509Certificate{SerialNumber: big.NewInt(serial)}, Status: models.StatusRevoked,
		RevocationTimestamp: time.Now(), RevocationReason: models.RevocationReason(1),
	})
}

func (f *crlFixture) settings(ca models.CACertificate, legacySKI *string, status models.CRLSettingsStatus) models.CRLSettings {
	return models.CRLSettings{
		CAID: ca.ID, LegacySKI: legacySKI, Status: status,
		Options: models.CRLSettingsOptions{
			SignerSerialNumber: ca.Certificate.SerialNumber, Validity: models.TimeDuration(time.Hour),
			RefreshInterval: models.TimeDuration(30 * time.Minute), RegenerateOnRevoke: true,
		},
		LatestCRL: models.LatestCRLMeta{Version: models.BigInt{Int: big.NewInt(0)}, ValidFrom: time.Now()},
	}
}

func serials(crl *x509.RevocationList) []int64 {
	var out []int64
	for _, e := range crl.RevokedCertificateEntries {
		out = append(out, e.SerialNumber.Int64())
	}
	slices.Sort(out)
	return out
}

// idpURLs returns the URLs of the Issuing Distribution Point of the CRL.
func idpURLs(t *testing.T, crl *x509.RevocationList) []string {
	t.Helper()
	for _, ext := range crl.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 28}) {
			continue
		}
		var idp struct {
			DistributionPoint asn1.RawValue `asn1:"tag:0,optional"`
		}
		_, err := asn1.Unmarshal(ext.Value, &idp)
		require.NoError(t, err)
		var urls []string
		rest := idp.DistributionPoint.Bytes // DistributionPointName [0] { fullName [0] { GeneralNames } }
		var fullName asn1.RawValue
		_, err = asn1.Unmarshal(rest, &fullName)
		require.NoError(t, err)
		names := fullName.Bytes
		for len(names) > 0 {
			var name asn1.RawValue
			names, err = asn1.Unmarshal(names, &name)
			require.NoError(t, err)
			urls = append(urls, string(name.Bytes))
		}
		slices.Sort(urls)
		return urls
	}
	t.Fatalf("CRL has no IDP")
	return nil
}

func TestInitCRLSettings(t *testing.T) {
	ctx := context.Background()

	t.Run("two CAs sharing a key get one settings each", func(t *testing.T) {
		f := newCRLFixture(t)
		f.addCA("ca-a", "Factory Root")
		f.addCA("ca-b", "Factory Root")

		a, err := f.svc.InitCRLSettings(ctx, "ca-a")
		require.NoError(t, err)
		b, err := f.svc.InitCRLSettings(ctx, "ca-b")
		require.NoError(t, err)

		require.Equal(t, "ca-a", a.CAID)
		require.Equal(t, "ca-b", b.CAID)
		require.Len(t, f.repo.rows, 2)
		for _, s := range f.repo.rows {
			require.Nil(t, s.LegacySKI, "new settings are not keyed by SKI")
			require.Equal(t, models.CRLSettingsActive, s.Status)
			require.Equal(t, models.TimeDuration(7*24*time.Hour), s.Options.Validity)
			require.True(t, s.Options.RegenerateOnRevoke)
			require.EqualValues(t, 1, s.LatestCRL.Version.Int64(), "the first CRL is generated")
		}
	})

	t.Run("a retried event does not fail nor duplicate", func(t *testing.T) {
		f := newCRLFixture(t)
		f.addCA("ca-a", "Root")
		_, err := f.svc.InitCRLSettings(ctx, "ca-a")
		require.NoError(t, err)
		_, err = f.svc.InitCRLSettings(ctx, "ca-a")
		require.NoError(t, err)
		require.Len(t, f.repo.rows, 1)
	})

	t.Run("an unknown CA", func(t *testing.T) {
		f := newCRLFixture(t)
		_, err := f.svc.InitCRLSettings(ctx, "nope")
		require.ErrorIs(t, err, errs.ErrCANotFound)
	})
}

func TestCalculateCRL(t *testing.T) {
	ctx := context.Background()

	t.Run("each CA lists only its own revocations", func(t *testing.T) {
		f := newCRLFixture(t)
		a, b := f.addCA("ca-a", "Factory Root"), f.addCA("ca-b", "Factory Root") // same subject, same key
		f.repo.rows["ca-a"], f.repo.rows["ca-b"] = f.settings(a, nil, models.CRLSettingsActive), f.settings(b, nil, models.CRLSettingsActive)
		f.revoke("ca-a", 1001)
		f.revoke("ca-b", 2002)

		crlA, err := f.svc.CalculateCRL(ctx, coreservices.CalculateCRLInput{CAID: "ca-a"})
		require.NoError(t, err)
		crlB, err := f.svc.CalculateCRL(ctx, coreservices.CalculateCRLInput{CAID: "ca-b"})
		require.NoError(t, err)

		require.Equal(t, []int64{1001}, serials(crlA))
		require.Equal(t, []int64{2002}, serials(crlB))
		_, err = f.bucket.ReadAll(ctx, "pki/va/crl/ca-a/1.crl")
		require.NoError(t, err)
		_, err = f.bucket.ReadAll(ctx, "pki/va/crl/ca-b/1.crl")
		require.NoError(t, err)
	})

	t.Run("the IDP holds the new URL and, for migrated settings, the old one", func(t *testing.T) {
		f := newCRLFixture(t, "va1.example.com", "va2.example.com")
		a, b := f.addCA("ca-a", "Root A"), f.addCA("ca-b", "Root B")
		legacy := "3f9a"
		f.repo.rows["ca-a"], f.repo.rows["ca-b"] = f.settings(a, &legacy, models.CRLSettingsActive), f.settings(b, nil, models.CRLSettingsActive)

		crlA, err := f.svc.CalculateCRL(ctx, coreservices.CalculateCRLInput{CAID: "ca-a"})
		require.NoError(t, err)
		crlB, err := f.svc.CalculateCRL(ctx, coreservices.CalculateCRLInput{CAID: "ca-b"})
		require.NoError(t, err)

		require.Equal(t, []string{"http://va1.example.com/crl/3f9a", "http://va1.example.com/crl/ca-a", "http://va2.example.com/crl/3f9a", "http://va2.example.com/crl/ca-a"}, idpURLs(t, crlA))
		require.Equal(t, []string{"http://va1.example.com/crl/ca-b", "http://va2.example.com/crl/ca-b"}, idpURLs(t, crlB))
	})

	t.Run("a lost update does not publish the file", func(t *testing.T) {
		f := newCRLFixture(t)
		a := f.addCA("ca-a", "Root")
		f.repo.rows["ca-a"] = f.settings(a, nil, models.CRLSettingsActive)
		f.repo.conflict = true

		_, err := f.svc.CalculateCRL(ctx, coreservices.CalculateCRLInput{CAID: "ca-a"})
		require.ErrorIs(t, err, errs.ErrCRLSettingsConflict)
		files, _, err := f.bucket.ListPage(ctx, blob.FirstPageToken, 10, &blob.ListOptions{Prefix: "pki/va/crl/ca-a/"})
		require.NoError(t, err)
		require.Empty(t, files, "neither the CRL nor any leftover of the attempt is in the bucket")
	})

	t.Run("archived settings are never regenerated", func(t *testing.T) {
		f := newCRLFixture(t)
		a := f.addCA("ca-a", "Root")
		f.repo.rows["ca-a"] = f.settings(a, nil, models.CRLSettingsArchived)
		_, err := f.svc.CalculateCRL(ctx, coreservices.CalculateCRLInput{CAID: "ca-a"})
		require.ErrorIs(t, err, errs.ErrCRLSettingsNotActive)
	})

	t.Run("unknown settings", func(t *testing.T) {
		f := newCRLFixture(t)
		_, err := f.svc.CalculateCRL(ctx, coreservices.CalculateCRLInput{CAID: "nope"})
		require.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)
	})
}

func TestCalculateCRLRestoresMetadataWhenPublicationFails(t *testing.T) {
	f := newCRLFixture(t)
	a := f.addCA("ca-a", "Root")
	f.repo.rows[a.ID] = f.settings(a, nil, models.CRLSettingsActive)
	_, err := f.svc.CalculateCRL(context.Background(), coreservices.CalculateCRLInput{CAID: a.ID})
	require.NoError(t, err)
	previous := f.repo.rows[a.ID].LatestCRL
	f.svc.vaRepo = &removeStagedAfterClaimRepo{memCRLSettingsRepo: f.repo, bucket: f.bucket}
	_, err = f.svc.CalculateCRL(context.Background(), coreservices.CalculateCRLInput{CAID: a.ID})
	require.Error(t, err)
	require.Equal(t, previous, f.repo.rows[a.ID].LatestCRL)
}

func TestGetCRLFallsBackWhenLatestIsMissing(t *testing.T) {
	f := newCRLFixture(t)
	a := f.addCA("ca-a", "Root")
	f.repo.rows[a.ID] = f.settings(a, nil, models.CRLSettingsActive)
	previous, err := f.svc.CalculateCRL(context.Background(), coreservices.CalculateCRLInput{CAID: a.ID})
	require.NoError(t, err)
	row := f.repo.rows[a.ID]
	row.LatestCRL.Version = models.BigInt{Int: big.NewInt(2)}
	f.repo.rows[a.ID] = row
	got, err := f.svc.GetCRL(context.Background(), coreservices.GetCRLInput{ID: a.ID, CRLVersion: big.NewInt(0)})
	require.NoError(t, err)
	require.Equal(t, previous.Raw, got.Raw)
	_, err = f.svc.GetCRL(context.Background(), coreservices.GetCRLInput{ID: a.ID, CRLVersion: big.NewInt(2)})
	require.ErrorIs(t, err, errs.ErrCRLNotFound)
}

func TestGetCRL(t *testing.T) {
	ctx := context.Background()
	f := newCRLFixture(t)
	a, b := f.addCA("ca-a", "Root A"), f.addCA("ca-b", "Root B")
	legacy := "3f9a"
	f.repo.rows["ca-a"], f.repo.rows["ca-b"] = f.settings(a, &legacy, models.CRLSettingsActive), f.settings(b, nil, models.CRLSettingsArchived)
	f.revoke("ca-a", 1001)
	_, err := f.svc.CalculateCRL(ctx, coreservices.CalculateCRLInput{CAID: "ca-a"})
	require.NoError(t, err)
	// ca-b was archived with a CRL already published.
	crlDer, err := f.bucket.ReadAll(ctx, "pki/va/crl/ca-a/1.crl")
	require.NoError(t, err)
	require.NoError(t, f.bucket.WriteAll(ctx, "pki/va/crl/ca-b/4.crl", crlDer, nil))
	row := f.repo.rows["ca-b"]
	row.LatestCRL.Version = models.BigInt{Int: big.NewInt(4)}
	f.repo.rows["ca-b"] = row

	get := func(id string, version int64) (*x509.RevocationList, error) {
		return f.svc.GetCRL(ctx, coreservices.GetCRLInput{ID: id, CRLVersion: big.NewInt(version)})
	}

	t.Run("by CA id and by legacy SKI it is the same CRL", func(t *testing.T) {
		byID, err := get("ca-a", 0)
		require.NoError(t, err)
		bySKI, err := get("3f9a", 0)
		require.NoError(t, err)
		require.True(t, bytes.Equal(byID.Raw, bySKI.Raw))
		require.Equal(t, []int64{1001}, serials(byID))
	})

	t.Run("a CA id wins over the SKI of other settings", func(t *testing.T) {
		clash := f.addCA("3f9a", "Other") // an id equal to the legacy SKI of ca-a
		f.repo.rows["3f9a"] = f.settings(clash, nil, models.CRLSettingsActive)
		defer delete(f.repo.rows, "3f9a")
		_, err := f.svc.CalculateCRL(ctx, coreservices.CalculateCRLInput{CAID: "3f9a"})
		require.NoError(t, err)

		got, err := get("3f9a", 0)
		require.NoError(t, err)
		require.Empty(t, serials(got), "it is the CRL of the CA with that id, not the legacy one of ca-a")
	})

	t.Run("a specific version of a migrated CA falls back to the SKI folder", func(t *testing.T) {
		require.NoError(t, f.bucket.WriteAll(ctx, "pki/va/crl/3f9a/9.crl", crlDer, nil))
		_, err := get("ca-a", 9)
		require.NoError(t, err)
		_, err = get("ca-b", 9)
		require.Error(t, err, "settings without legacy SKI have no fallback")
	})

	t.Run("archived settings still serve their last CRL", func(t *testing.T) {
		_, err := get("ca-b", 0)
		require.NoError(t, err)
	})

	t.Run("unknown id", func(t *testing.T) {
		_, err := get("nope", 0)
		require.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)
	})

	t.Run("settings that never published a CRL", func(t *testing.T) {
		c := f.addCA("ca-c", "Root C")
		f.repo.rows["ca-c"] = f.settings(c, nil, models.CRLSettingsActive)
		_, err := get("ca-c", 0)
		require.ErrorIs(t, err, errs.ErrCRLNotFound)
	})
}

func TestUpdateCRLSettings(t *testing.T) {
	ctx := context.Background()
	newInput := func(f *crlFixture, ca models.CACertificate, mutate func(*models.CRLSettingsOptions)) coreservices.UpdateCRLSettingsInput {
		o := f.settings(ca, nil, models.CRLSettingsActive).Options
		mutate(&o)
		return coreservices.UpdateCRLSettingsInput{CAID: ca.ID, Options: o}
	}

	t.Run("not active is a conflict", func(t *testing.T) {
		f := newCRLFixture(t)
		a := f.addCA("ca-a", "Root")
		f.repo.rows["ca-a"] = f.settings(a, nil, models.CRLSettingsArchived)
		_, err := f.svc.UpdateCRLSettings(ctx, newInput(f, a, func(*models.CRLSettingsOptions) {}))
		require.ErrorIs(t, err, errs.ErrCRLSettingsNotActive)
	})

	t.Run("unknown settings", func(t *testing.T) {
		f := newCRLFixture(t)
		a := f.addCA("ca-a", "Root")
		_, err := f.svc.UpdateCRLSettings(ctx, newInput(f, a, func(*models.CRLSettingsOptions) {}))
		require.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)
	})

	t.Run("the signer is validated only when it changes", func(t *testing.T) {
		f := newCRLFixture(t)
		a := f.addCA("ca-a", "Root")
		row := f.settings(a, nil, models.CRLSettingsActive)
		row.Options.SignerSerialNumber = "gone" // a signer that no longer validates must not block other edits (#841)
		f.repo.rows["ca-a"] = row

		in := newInput(f, a, func(o *models.CRLSettingsOptions) {
			o.SignerSerialNumber = "gone"
			o.Validity = models.TimeDuration(3 * time.Hour)
		})
		got, err := f.svc.UpdateCRLSettings(ctx, in)
		require.NoError(t, err)
		require.Equal(t, models.TimeDuration(3*time.Hour), got.Options.Validity)
	})

	t.Run("a new signer must have cRLSign and the identity of the CA", func(t *testing.T) {
		f := newCRLFixture(t)
		a := f.addCA("ca-a", "Root")
		f.repo.rows["ca-a"] = f.settings(a, nil, models.CRLSettingsActive)

		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		noSign := f.newCert("Root", x509.KeyUsageDigitalSignature, false, f.key)
		otherKeyCert := f.newCert("Root", x509.KeyUsageCRLSign, false, otherKey)
		otherSubject := f.newCert("Another name", x509.KeyUsageCRLSign, false, f.key)
		reissued := f.newCert("Root", x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true, f.key)

		for name, serial := range map[string]string{"no cRLSign": noSign.SerialNumber, "other key": otherKeyCert.SerialNumber, "other subject": otherSubject.SerialNumber} {
			_, err := f.svc.UpdateCRLSettings(ctx, newInput(f, a, func(o *models.CRLSettingsOptions) { o.SignerSerialNumber = serial }))
			require.ErrorIs(t, err, errs.ErrValidateBadRequest, name)
		}
		_, err = f.svc.UpdateCRLSettings(ctx, newInput(f, a, func(o *models.CRLSettingsOptions) { o.SignerSerialNumber = "missing" }))
		require.ErrorIs(t, err, errs.ErrCertificateNotFound)

		got, err := f.svc.UpdateCRLSettings(ctx, newInput(f, a, func(o *models.CRLSettingsOptions) { o.SignerSerialNumber = reissued.SerialNumber }))
		require.NoError(t, err, "any certificate of the CA identity is a valid signer, not only its current one")
		require.Equal(t, reissued.SerialNumber, got.Options.SignerSerialNumber)
	})

	t.Run("a missing signer is a bad request", func(t *testing.T) {
		f := newCRLFixture(t)
		a := f.addCA("ca-a", "Root")
		f.repo.rows["ca-a"] = f.settings(a, nil, models.CRLSettingsActive)
		_, err := f.svc.UpdateCRLSettings(ctx, newInput(f, a, func(o *models.CRLSettingsOptions) { o.SignerSerialNumber = "" }))
		require.ErrorIs(t, err, errs.ErrValidateBadRequest)
	})
}
