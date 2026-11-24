package services

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// Pure unit test (no Docker): the CA key must only sign while the CA is ACTIVE and inside its
// validity window. The stored status can lag behind the dates (the expiration monitor runs
// periodically), so the dates are checked too. Rejection happens before any KMS call.
func TestSignCertificateRejectsUnusableCA(t *testing.T) {
	now := time.Now()

	for _, tc := range []struct {
		name      string
		status    models.CertificateStatus
		validFrom time.Time
		validTo   time.Time
	}{
		{name: "revoked", status: models.StatusRevoked, validFrom: now.Add(-time.Hour), validTo: now.Add(time.Hour)},
		{name: "expired status", status: models.StatusExpired, validFrom: now.Add(-2 * time.Hour), validTo: now.Add(-time.Hour)},
		{name: "inactive", status: models.StatusInactive, validFrom: now.Add(-time.Hour), validTo: now.Add(time.Hour)},
		{name: "active but past NotAfter", status: models.StatusActive, validFrom: now.Add(-2 * time.Hour), validTo: now.Add(-time.Minute)},
		{name: "active but before NotBefore", status: models.StatusActive, validFrom: now.Add(time.Hour), validTo: now.Add(2 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := models.CACertificate{ID: "ca-1", ProfileID: "default"}
			ca.Certificate.Status = tc.status
			ca.Certificate.ValidFrom = tc.validFrom
			ca.Certificate.ValidTo = tc.validTo

			svc, err := NewCAService(CAServiceBuilder{
				Logger:    logrus.NewEntry(logrus.New()),
				CAStorage: &signAsCACARepo{ca: ca},
				IssuanceProfileStorage: &signAsCAProfileRepo{profiles: map[string]models.IssuanceProfile{
					"default": {ID: "default"},
				}},
			})
			require.NoError(t, err)

			_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
				CAID:        "ca-1",
				CertRequest: &models.X509CertificateRequest{},
			})

			require.ErrorIs(t, err, errs.ErrCAStatus)
		})
	}
}
