package services

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// Pure unit test (no Docker): the exported SignCertificate must never issue a CA certificate,
// whatever the source of the profile. Rejection happens before any signing, so fake repos suffice.

type signAsCACARepo struct {
	storage.CACertificatesRepo
	ca models.CACertificate
}

func (r *signAsCACARepo) SelectExistsByID(context.Context, string) (bool, *models.CACertificate, error) {
	return true, &r.ca, nil
}

type signAsCAProfileRepo struct {
	storage.IssuanceProfileRepo
	profiles map[string]models.IssuanceProfile
}

func (r *signAsCAProfileRepo) SelectByID(_ context.Context, id string) (bool, *models.IssuanceProfile, error) {
	p, ok := r.profiles[id]
	return ok, &p, nil
}

func TestSignCertificateNeverIssuesACA(t *testing.T) {
	ca := models.CACertificate{ID: "ca-1", ProfileID: "default"}
	ca.Certificate.Status = models.StatusActive
	ca.Certificate.ValidFrom = time.Now().Add(-time.Hour)
	ca.Certificate.ValidTo = time.Now().Add(time.Hour)

	for _, tc := range []struct {
		name      string
		input     services.SignCertificateInput
		defaultCA bool // the CA's own default profile is a CA profile
	}{
		{name: "inline profile", input: services.SignCertificateInput{IssuanceProfile: &models.IssuanceProfile{SignAsCA: true}}},
		{name: "profile by ID", input: services.SignCertificateInput{IssuanceProfileID: "ca-profile"}},
		{name: "CA default profile", input: services.SignCertificateInput{}, defaultCA: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := NewCAService(CAServiceBuilder{
				Logger:    logrus.NewEntry(logrus.New()),
				CAStorage: &signAsCACARepo{ca: ca},
				IssuanceProfileStorage: &signAsCAProfileRepo{profiles: map[string]models.IssuanceProfile{
					"ca-profile": {ID: "ca-profile", SignAsCA: true},
					"default":    {ID: "default", SignAsCA: tc.defaultCA},
				}},
			})
			require.NoError(t, err)

			tc.input.CAID = "ca-1"
			tc.input.CertRequest = &models.X509CertificateRequest{}
			_, err = svc.SignCertificate(context.Background(), tc.input)

			require.ErrorIs(t, err, errs.ErrSignAsCANotAllowed)
		})
	}
}
