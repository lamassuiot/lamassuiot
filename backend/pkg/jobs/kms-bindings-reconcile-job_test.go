package jobs

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// keyUsersRepo serves the certificates that use a key, paged by serial number like the SQL store.
type keyUsersRepo struct {
	storage.CertificatesRepo
	users []models.CertificateKeyRef
}

func (repo *keyUsersRepo) SelectKeyUsersAfter(_ context.Context, after string, limit int) ([]models.CertificateKeyRef, error) {
	page := []models.CertificateKeyRef{}
	for _, u := range repo.users {
		if u.SerialNumber > after && len(page) < limit {
			page = append(page, u)
		}
	}
	return page, nil
}

// reconcileKMS records the reconciliation requests it gets.
type reconcileKMS struct {
	services.KMSService
	calls   []services.ReconcileCertificateBindingsInput
	failOn  int // 1-based call that fails; 0 never fails
	perCall models.ReconcileStats
}

func (kms *reconcileKMS) ReconcileCertificateBindings(_ context.Context, input services.ReconcileCertificateBindingsInput) (*models.ReconcileStats, error) {
	kms.calls = append(kms.calls, input)
	if len(kms.calls) == kms.failOn {
		return nil, errors.New("kms unavailable")
	}
	stats := kms.perCall
	return &stats, nil
}

func refs(serials ...string) []models.CertificateKeyRef {
	out := []models.CertificateKeyRef{}
	for _, s := range serials {
		out = append(out, models.CertificateKeyRef{SerialNumber: s, KeyID: "key-" + s, EngineID: "engine"})
	}
	return out
}

type reconcileRange struct {
	after, upTo string
	serials     []string
}

func rangesOf(calls []services.ReconcileCertificateBindingsInput) []reconcileRange {
	out := []reconcileRange{}
	for _, c := range calls {
		r := reconcileRange{after: c.After, upTo: c.UpTo, serials: []string{}}
		for _, b := range c.Bindings {
			r.serials = append(r.serials, b.SerialNumber)
		}
		out = append(out, r)
	}
	return out
}

func newTestReconciler(repo *keyUsersRepo, kms *reconcileKMS) *KMSBindingsReconciler {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return NewKMSBindingsReconciler(repo, kms, logrus.NewEntry(logger), 2, 5*time.Minute)
}

// The ranges cover every serial with no gap, and the last one is open so that stale bindings after the
// last certificate are removed too.
func TestKMSBindingsReconcilerCoversEverySerial(t *testing.T) {
	for _, tc := range []struct {
		name  string
		users []models.CertificateKeyRef
		want  []reconcileRange
	}{
		{
			name:  "last page shorter than the batch",
			users: refs("s1", "s2", "s3", "s4", "s5"),
			want: []reconcileRange{
				{after: "", upTo: "s2", serials: []string{"s1", "s2"}},
				{after: "s2", upTo: "s4", serials: []string{"s3", "s4"}},
				{after: "s4", upTo: "", serials: []string{"s5"}},
			},
		},
		{
			name:  "last page exactly the batch size",
			users: refs("s1", "s2"),
			want: []reconcileRange{
				{after: "", upTo: "s2", serials: []string{"s1", "s2"}},
				{after: "s2", upTo: "", serials: []string{}},
			},
		},
		{
			name: "no certificate uses a key",
			want: []reconcileRange{{after: "", upTo: "", serials: []string{}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kms := &reconcileKMS{perCall: models.ReconcileStats{Added: 1, Removed: 2, MissingKeys: 3}}
			stats, err := newTestReconciler(&keyUsersRepo{users: tc.users}, kms).Reconcile(context.Background())
			require.NoError(t, err)

			require.Equal(t, tc.want, rangesOf(kms.calls))
			for _, c := range kms.calls {
				require.Equal(t, 5*time.Minute, c.MinAge)
			}
			n := len(tc.want)
			require.Equal(t, models.ReconcileStats{Added: n, Removed: 2 * n, MissingKeys: 3 * n}, stats)
		})
	}
}

func TestKMSBindingsReconcilerStopsOnKMSError(t *testing.T) {
	kms := &reconcileKMS{failOn: 2}
	_, err := newTestReconciler(&keyUsersRepo{users: refs("s1", "s2", "s3", "s4", "s5")}, kms).Reconcile(context.Background())
	require.Error(t, err)
	require.Len(t, kms.calls, 2, "a failed batch stops the run; the next run starts over")
}
