package jobs

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
)

// KMSBindingsReconciler makes the KMS key bindings match the certificates that use each key. The CA
// owns which certificate uses which key; the KMS owns the bindings that keep a key in use from being
// deleted. Bindings are written as certificates are stored, and this job repairs what a failed or
// missed call left behind.
type KMSBindingsReconciler struct {
	certs     storage.CertificatesRepo
	kms       services.KMSService
	logger    *logrus.Entry
	batchSize int
	minAge    time.Duration
}

func NewKMSBindingsReconciler(certs storage.CertificatesRepo, kms services.KMSService, logger *logrus.Entry, batchSize int, minAge time.Duration) *KMSBindingsReconciler {
	return &KMSBindingsReconciler{certs: certs, kms: kms, logger: logger, batchSize: batchSize, minAge: minAge}
}

func (r *KMSBindingsReconciler) Run() {
	ctx := helpers.InitJobContext("kms-bindings-reconcile")
	lFunc := helpers.ConfigureLogger(ctx, r.logger)

	stats, err := r.Reconcile(ctx)
	if err != nil {
		lFunc.Errorf("could not reconcile KMS key bindings: %s", err)
		return
	}
	lFunc.Infof("reconciled KMS key bindings: %d added, %d removed, %d for keys not in the KMS", stats.Added, stats.Removed, stats.MissingKeys)
}

// Reconcile walks the certificates that use a key in batches, by serial number, and asks the KMS to
// make the bindings in each serial range exactly those. The ranges cover every serial with no gap,
// and the last one is open so that stale bindings after the last certificate are removed too.
// Bindings younger than minAge are left alone: their certificates may postdate the batch read.
func (r *KMSBindingsReconciler) Reconcile(ctx context.Context) (models.ReconcileStats, error) {
	total := models.ReconcileStats{}
	after := ""
	for {
		users, err := r.certs.SelectKeyUsersAfter(ctx, after, r.batchSize)
		if err != nil {
			return total, err
		}

		upTo := ""
		if len(users) == r.batchSize {
			upTo = users[len(users)-1].SerialNumber
		}

		stats, err := r.kms.ReconcileCertificateBindings(ctx, services.ReconcileCertificateBindingsInput{
			After: after, UpTo: upTo, MinAge: r.minAge, Bindings: users,
		})
		if err != nil {
			return total, err
		}
		total.Added += stats.Added
		total.Removed += stats.Removed
		total.MissingKeys += stats.MissingKeys

		if upTo == "" {
			return total, nil
		}
		after = upTo
	}
}
