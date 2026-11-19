package services

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"
	"golang.org/x/crypto/ocsp"
)

// readCRL reads a published CRL version of a CA from the bucket.
func (f *crlFixture) readCRL(caID, version string) *x509.RevocationList {
	f.t.Helper()
	data, err := f.bucket.ReadAll(context.Background(), crlObjectKey(caID, version))
	require.NoError(f.t, err)
	block, _ := pem.Decode(data)
	require.NotNil(f.t, block)
	crl, err := x509.ParseRevocationList(block.Bytes)
	require.NoError(f.t, err)
	return crl
}

func (f *crlFixture) crlFiles(caID string) int {
	f.t.Helper()
	files, _, err := f.bucket.ListPage(context.Background(), blob.FirstPageToken, 100, &blob.ListOptions{Prefix: "pki/va/crl/" + caID + "/"})
	require.NoError(f.t, err)
	return len(files)
}

// lifecycleCA adds a CA valid for two more days, in the given status, with ACTIVE settings.
func (f *crlFixture) lifecycleCA(id string, status models.CertificateStatus, reason int) models.CACertificate {
	ca := f.addCA(id, "Root "+id)
	ca.Certificate.ValidTo = time.Now().Add(48 * time.Hour).Truncate(time.Second).UTC()
	ca.Certificate.Status = status
	ca.Certificate.RevocationReason = models.RevocationReason(reason)
	f.cas[id] = ca
	f.certs[ca.Certificate.SerialNumber] = ca.Certificate
	f.repo.rows[id] = f.settings(ca, nil, models.CRLSettingsActive)
	return ca
}

func TestCalculateCRLDoesNotReadTheCA(t *testing.T) {
	f := newCRLFixture(t)
	f.lifecycleCA("ca-a", models.StatusActive, 0)
	f.revoke("ca-a", 1001)
	delete(f.cas, "ca-a") // GetCAByID now fails: the CRL only needs the stored settings and signer

	crl, err := f.svc.CalculateCRL(context.Background(), coreservices.CalculateCRLInput{CAID: "ca-a"})
	require.NoError(t, err)
	require.Equal(t, []int64{1001}, serials(crl))
}

func TestFinalizeCRLSettingsIssuesTheFinalCRL(t *testing.T) {
	ctx := context.Background()
	f := newCRLFixture(t)
	ca := f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)
	f.revoke("ca-a", 1001)

	got, finalCRL, err := f.svc.FinalizeCRLSettings(ctx, coreservices.FinalizeCRLSettingsInput{CAID: "ca-a", FinalCRL: true, FinalCRLNextUpdate: ca.Certificate.ValidTo})
	require.NoError(t, err)
	require.Equal(t, models.CRLSettingsFinal, got.Status)
	require.NotNil(t, finalCRL, "the final CRL issued by the call is returned, so that it can be announced")
	require.Equal(t, "1", finalCRL.Number.String())
	require.Equal(t, []int64{1001}, serials(finalCRL))
	require.Nil(t, got.SignerEngineID)
	require.Nil(t, got.SignerKeyID)
	require.Equal(t, ca.Certificate.SerialNumber, got.Options.SignerSerialNumber)

	crl := f.readCRL("ca-a", "1")
	require.True(t, crl.NextUpdate.Equal(ca.Certificate.ValidTo), "final CRL valid until the CA expires, got %s", crl.NextUpdate)
	require.Equal(t, []int64{1001}, serials(crl))

	t.Run("a retry publishes nothing", func(t *testing.T) {
		again, againCRL, err := f.svc.FinalizeCRLSettings(ctx, coreservices.FinalizeCRLSettingsInput{CAID: "ca-a", FinalCRL: true, FinalCRLNextUpdate: ca.Certificate.ValidTo})
		require.NoError(t, err)
		require.Equal(t, models.CRLSettingsFinal, again.Status)
		require.Nil(t, againCRL, "no CRL was issued, so there is none to announce")
		require.Equal(t, 1, f.crlFiles("ca-a"))
	})
}

// interveningCRLRepo simulates a regular CRL generated between the publication of the final CRL and its transition to
// FINAL: the first MarkFinal finds a newer version.
type interveningCRLRepo struct {
	*memCRLSettingsRepo
	intervened bool
}

func (r *interveningCRLRepo) MarkFinal(ctx context.Context, id string, latestVersion *big.Int) error {
	if !r.intervened && latestVersion != nil {
		r.intervened = true
		next := new(big.Int).Add(latestVersion, big.NewInt(1))
		if err := r.UpdateLatestCRL(ctx, id, latestVersion, models.LatestCRLMeta{
			Version: models.BigInt{Int: next}, ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour),
		}); err != nil {
			return err
		}
	}
	return r.memCRLSettingsRepo.MarkFinal(ctx, id, latestVersion)
}

// A short-lived CRL must never replace the final one: when another CRL wins the version, the final CRL is issued again.
func TestFinalizeCRLSettingsReissuesTheFinalCRLAfterAConcurrentOne(t *testing.T) {
	f := newCRLFixture(t)
	ca := f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)
	repo := &interveningCRLRepo{memCRLSettingsRepo: f.repo}
	f.svc.vaRepo = repo

	got, finalCRL, err := f.svc.FinalizeCRLSettings(context.Background(), coreservices.FinalizeCRLSettingsInput{CAID: "ca-a", FinalCRL: true, FinalCRLNextUpdate: ca.Certificate.ValidTo})
	require.NoError(t, err)
	require.True(t, repo.intervened)
	require.Equal(t, models.CRLSettingsFinal, got.Status)
	require.Equal(t, "3", finalCRL.Number.String(), "the CRL returned is the one that stayed as the final one")
	require.Equal(t, "3", got.LatestCRL.Version.String(), "final (1), intervening (2), final again (3)")
	require.True(t, f.readCRL("ca-a", "3").NextUpdate.Equal(ca.Certificate.ValidTo))
}

// concurrentFinalizerRepo simulates another finalizer, such as the monitor job, that issues the final CRL and moves
// the settings to FINAL while this one is generating its own: this one then finds them no longer ACTIVE.
type concurrentFinalizerRepo struct {
	*memCRLSettingsRepo
	finalized bool
}

func (r *concurrentFinalizerRepo) UpdateLatestCRL(ctx context.Context, id string, expected *big.Int, latest models.LatestCRLMeta) error {
	if !r.finalized {
		r.finalized = true
		if err := r.memCRLSettingsRepo.UpdateLatestCRL(ctx, id, expected, latest); err != nil {
			return err
		}
		if err := r.memCRLSettingsRepo.MarkFinal(ctx, id, latest.Version.Int); err != nil {
			return err
		}
	}
	return r.memCRLSettingsRepo.UpdateLatestCRL(ctx, id, expected, latest)
}

// Losing the transition to another finalizer is not an error: the settings are FINAL, which is what was asked for.
func TestFinalizeCRLSettingsAfterAConcurrentFinalizer(t *testing.T) {
	f := newCRLFixture(t)
	ca := f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)
	repo := &concurrentFinalizerRepo{memCRLSettingsRepo: f.repo}
	f.svc.vaRepo = repo

	got, finalCRL, err := f.svc.FinalizeCRLSettings(context.Background(), coreservices.FinalizeCRLSettingsInput{CAID: "ca-a", FinalCRL: true, FinalCRLNextUpdate: ca.Certificate.ValidTo})
	require.NoError(t, err)
	require.True(t, repo.finalized)
	require.Equal(t, models.CRLSettingsFinal, got.Status)
	require.Nil(t, finalCRL, "the other finalizer issued the final CRL: announcing it is up to that one")
	require.Equal(t, "1", got.LatestCRL.Version.String(), "the final CRL of the other finalizer")
}

func TestFinalizeCRLSettingsWithoutCRL(t *testing.T) {
	f := newCRLFixture(t)
	f.lifecycleCA("ca-a", models.StatusExpired, 0)

	got, finalCRL, err := f.svc.FinalizeCRLSettings(context.Background(), coreservices.FinalizeCRLSettingsInput{CAID: "ca-a"})
	require.NoError(t, err)
	require.Equal(t, models.CRLSettingsFinal, got.Status)
	require.Nil(t, finalCRL)
	require.Zero(t, f.crlFiles("ca-a"), "a CRL signed by an expired CA is not trusted")
}

func TestFinalizeCRLSettingsRequiresNextUpdateForTheFinalCRL(t *testing.T) {
	f := newCRLFixture(t)
	f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)

	_, _, err := f.svc.FinalizeCRLSettings(context.Background(), coreservices.FinalizeCRLSettingsInput{CAID: "ca-a", FinalCRL: true})
	require.ErrorIs(t, err, errs.ErrValidateBadRequest)
	require.Zero(t, f.crlFiles("ca-a"), "nothing is published when the input is rejected")
}

func TestReconcileCRLSettings(t *testing.T) {
	for _, tc := range []struct {
		name       string
		setup      func(f *crlFixture)
		wantStatus models.CRLSettingsStatus
		wantCRLs   int
	}{
		{name: "CA deleted", setup: func(f *crlFixture) {
			f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)
			delete(f.cas, "ca-a")
		},
			wantStatus: models.CRLSettingsArchived, wantCRLs: 1},
		{name: "final settings of a deleted CA", setup: func(f *crlFixture) {
			ca := f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)
			f.repo.rows["ca-a"] = f.settings(ca, nil, models.CRLSettingsFinal)
			delete(f.cas, "ca-a")
		}, wantStatus: models.CRLSettingsArchived},
		{name: "CA revoked", setup: func(f *crlFixture) { f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise) },
			wantStatus: models.CRLSettingsFinal, wantCRLs: 1},
		{name: "CA on hold", setup: func(f *crlFixture) { f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.CertificateHold) },
			wantStatus: models.CRLSettingsActive},
		{name: "CA expired", setup: func(f *crlFixture) { f.lifecycleCA("ca-a", models.StatusExpired, 0) },
			wantStatus: models.CRLSettingsFinal},
		{name: "CA revoked after its expiration date", setup: func(f *crlFixture) {
			ca := f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)
			ca.Certificate.ValidTo = time.Now().Add(-time.Minute)
			f.cas["ca-a"] = ca
		}, wantStatus: models.CRLSettingsFinal},
		{name: "CA active", setup: func(f *crlFixture) { f.lifecycleCA("ca-a", models.StatusActive, 0) },
			wantStatus: models.CRLSettingsActive},
		{name: "final settings of an existing CA", setup: func(f *crlFixture) {
			ca := f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)
			f.repo.rows["ca-a"] = f.settings(ca, nil, models.CRLSettingsFinal)
		}, wantStatus: models.CRLSettingsFinal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCRLFixture(t)
			tc.setup(f)

			got, err := f.svc.ReconcileCRLSettings(context.Background(), coreservices.ReconcileCRLSettingsInput{CAID: "ca-a"})
			require.NoError(t, err)
			require.Equal(t, tc.wantStatus, got.Status)
			require.Equal(t, tc.wantStatus, f.repo.rows["ca-a"].Status)
			require.Equal(t, tc.wantCRLs, f.crlFiles("ca-a"))
		})
	}

	t.Run("unknown settings", func(t *testing.T) {
		f := newCRLFixture(t)
		_, err := f.svc.ReconcileCRLSettings(context.Background(), coreservices.ReconcileCRLSettingsInput{CAID: "nope"})
		require.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)
	})
}

func TestArchiveCRLSettingsIsIdempotent(t *testing.T) {
	f := newCRLFixture(t)
	f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)
	for range 2 {
		got, err := f.svc.ArchiveCRLSettings(context.Background(), coreservices.ArchiveCRLSettingsInput{CAID: "ca-a"})
		require.NoError(t, err)
		require.Equal(t, models.CRLSettingsArchived, got.Status)
	}
	_, err := f.svc.ArchiveCRLSettings(context.Background(), coreservices.ArchiveCRLSettingsInput{CAID: "nope"})
	require.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)
}

func TestDeleteCRLSettingsOnlyArchived(t *testing.T) {
	ctx := context.Background()
	f := newCRLFixture(t)
	f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)
	require.NoError(t, f.bucket.WriteAll(ctx, crlObjectKey("ca-a", "1"), []byte("crl"), nil))

	require.ErrorIs(t, f.svc.DeleteCRLSettings(ctx, coreservices.DeleteCRLSettingsInput{CAID: "ca-a"}), errs.ErrCRLSettingsNotArchived)
	require.ErrorIs(t, f.svc.DeleteCRLSettings(ctx, coreservices.DeleteCRLSettingsInput{CAID: "nope"}), errs.ErrCRLSettingsNotFound)
	require.ErrorIs(t, f.svc.DeleteCRLSettings(ctx, coreservices.DeleteCRLSettingsInput{}), errs.ErrValidateBadRequest)

	_, err := f.svc.ArchiveCRLSettings(ctx, coreservices.ArchiveCRLSettingsInput{CAID: "ca-a"})
	require.NoError(t, err)
	require.NoError(t, f.svc.DeleteCRLSettings(ctx, coreservices.DeleteCRLSettingsInput{CAID: "ca-a"}))
	require.NotContains(t, f.repo.rows, "ca-a")
	require.Equal(t, 1, f.crlFiles("ca-a"), "published CRLs stay in the bucket")
}

func TestCRLSettingsSignerKey(t *testing.T) {
	ctx := context.Background()

	t.Run("init stores the key of the CA certificate", func(t *testing.T) {
		f := newCRLFixture(t)
		f.addCA("ca-a", "Root")
		_, err := f.svc.InitCRLSettings(ctx, "ca-a")
		require.NoError(t, err)
		row := f.repo.rows["ca-a"]
		require.Equal(t, "engine", deref(row.SignerEngineID))
		require.Equal(t, "key", deref(row.SignerKeyID))
	})

	t.Run("a new signer brings its key", func(t *testing.T) {
		f := newCRLFixture(t)
		a := f.lifecycleCA("ca-a", models.StatusActive, 0)
		reissued := f.newCert("Root ca-a", x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true, f.key)
		reissued.EngineID, reissued.KeyID = "engine2", "key2"
		f.certs[reissued.SerialNumber] = reissued

		opts := f.settings(a, nil, models.CRLSettingsActive).Options
		opts.SignerSerialNumber = reissued.SerialNumber
		_, err := f.svc.UpdateCRLSettings(ctx, coreservices.UpdateCRLSettingsInput{CAID: "ca-a", Options: opts})
		require.NoError(t, err)
		row := f.repo.rows["ca-a"]
		require.Equal(t, "engine2", deref(row.SignerEngineID))
		require.Equal(t, "key2", deref(row.SignerKeyID))
	})

	t.Run("a new signer without key is rejected", func(t *testing.T) {
		f := newCRLFixture(t)
		a := f.lifecycleCA("ca-a", models.StatusActive, 0)
		noKey := f.newCert("Root ca-a", x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true, f.key)
		noKey.KeyID = ""
		f.certs[noKey.SerialNumber] = noKey

		opts := f.settings(a, nil, models.CRLSettingsActive).Options
		opts.SignerSerialNumber = noKey.SerialNumber
		_, err := f.svc.UpdateCRLSettings(ctx, coreservices.UpdateCRLSettingsInput{CAID: "ca-a", Options: opts})
		require.ErrorIs(t, err, errs.ErrValidateBadRequest)
		require.Equal(t, a.Certificate.SerialNumber, f.repo.rows["ca-a"].Options.SignerSerialNumber)
	})
}

// While the CA exists, the stored signer is still checked against its identity: the database only knows the signer is
// a certificate, not that it can sign the CRL of this CA.
func TestCalculateCRLChecksTheSignerWhileTheCAExists(t *testing.T) {
	f := newCRLFixture(t)
	f.lifecycleCA("ca-a", models.StatusActive, 0)
	other := f.addCA("ca-b", "Another root")
	row := f.repo.rows["ca-a"]
	row.Options.SignerSerialNumber = other.Certificate.SerialNumber
	f.repo.rows["ca-a"] = row

	_, err := f.svc.CalculateCRL(context.Background(), coreservices.CalculateCRLInput{CAID: "ca-a"})
	require.ErrorIs(t, err, errs.ErrValidateBadRequest)
}

// Settings still ACTIVE when their CA is gone (its signer was not among the certificates the CA released, or an event
// was lost) still retain the key: they get a final CRL, valid until their signer expires, before they are archived.
func TestArchivingActiveSettingsIssuesTheirFinalCRL(t *testing.T) {
	f := newCRLFixture(t)
	ca := f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)
	f.revoke("ca-a", 1001)
	delete(f.cas, "ca-a")

	got, err := f.svc.ArchiveCRLSettings(context.Background(), coreservices.ArchiveCRLSettingsInput{CAID: "ca-a"})
	require.NoError(t, err)
	require.Equal(t, models.CRLSettingsArchived, got.Status)
	crl := f.readCRL("ca-a", "1")
	require.True(t, crl.NextUpdate.Equal(ca.Certificate.ValidTo), "valid until the signer expires, got %s", crl.NextUpdate)
	require.Equal(t, []int64{1001}, serials(crl))
}

// UpdateCAStatus stores the CA as revoked before it revokes its certificates one by one: a final CRL issued meanwhile
// would miss the rest. The monitor leaves recent revocations to the ca.status.update event, published once it is done.
func TestReconcileCRLSettingsLeavesRecentRevocationsToTheEvent(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		revokedAgo time.Duration
		want       models.CRLSettingsStatus
	}{
		{name: "recent", revokedAgo: time.Minute, want: models.CRLSettingsActive},
		{name: "old", revokedAgo: 2 * time.Hour, want: models.CRLSettingsFinal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCRLFixture(t)
			ca := f.lifecycleCA("ca-a", models.StatusRevoked, ocsp.KeyCompromise)
			ca.Certificate.RevocationTimestamp = time.Now().Add(-tc.revokedAgo)
			f.cas["ca-a"] = ca

			got, err := f.svc.ReconcileCRLSettings(ctx, coreservices.ReconcileCRLSettingsInput{CAID: "ca-a", RevokedBefore: time.Now().Add(-time.Hour)})
			require.NoError(t, err)
			require.Equal(t, tc.want, got.Status)
		})
	}
}
