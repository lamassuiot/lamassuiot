package dmsmanager

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"testing"
	"uuid"

	"github.com/globalsign/est"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The CommonName of a device certificate is the device ID. A DMS must not issue with an issuance profile that
// replaces it: that happens when the profile does not honor the CSR subject and sets a CommonName of its own.

func overrideProfileCN(p models.IssuanceProfile) models.IssuanceProfile {
	p.HonorSubject = false
	p.Subject = models.Subject{CommonName: "ES"}
	return p
}

func overrideFixtureProfileCN(t *testing.T, fx enrollBindFixture) {
	t.Helper()
	_, err := fx.testServers.CA.Service.UpdateIssuanceProfile(context.Background(), services.UpdateIssuanceProfileInput{
		Profile: overrideProfileCN(*fx.profile),
	})
	require.NoError(t, err, "could not update issuance profile")
}

func countCertificatesIssuedBy(t *testing.T, fx enrollBindFixture, caID string) int {
	t.Helper()
	count := 0
	_, err := fx.testServers.CA.Service.GetCertificatesByCA(context.Background(), services.GetCertificatesByCAInput{
		CAID: caID,
		ListInput: resources.ListInput[models.Certificate]{
			ExhaustiveRun: true,
			ApplyFunc:     func(models.Certificate) { count++ },
		},
	})
	require.NoError(t, err, "could not list certificates of CA %s", caID)
	return count
}

func TestSaveDMSRejectsIssuanceProfileOverridingCN(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		// settings returns DMS settings whose effective issuance profile overrides the CommonName.
		settings func(t *testing.T, fx enrollBindFixture) models.DMSSettings
	}{
		{
			name: "IssuanceProfileID",
			settings: func(t *testing.T, fx enrollBindFixture) models.DMSSettings {
				p, err := fx.testServers.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
					Profile: overrideProfileCN(models.IssuanceProfile{Validity: fx.profile.Validity}),
				})
				require.NoError(t, err, "could not create issuance profile")
				s := fx.dms.Settings
				s.IssuanceProfileID = p.ID
				return s
			},
		},
		{
			name: "InlineIssuanceProfile",
			settings: func(t *testing.T, fx enrollBindFixture) models.DMSSettings {
				p := overrideProfileCN(models.IssuanceProfile{Validity: fx.profile.Validity})
				s := fx.dms.Settings
				s.IssuanceProfile = &p
				return s
			},
		},
		{
			name: "EnrollmentCADefaultProfile",
			settings: func(t *testing.T, fx enrollBindFixture) models.DMSSettings {
				overrideFixtureProfileCN(t, fx)
				return fx.dms.Settings
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/Create", func(t *testing.T) {
			fx := newEnrollBindFixture(t)
			_, err := fx.dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
				ID:       uuid.NewV7().String(),
				Name:     "TestDMS",
				Metadata: map[string]any{},
				Settings: tc.settings(t, fx),
			})
			require.ErrorIs(t, err, errs.ErrValidateBadRequest)
			require.ErrorIs(t, err, errs.ErrDMSIssuanceProfileOverridesCN)
		})

		t.Run(tc.name+"/Update", func(t *testing.T) {
			fx := newEnrollBindFixture(t)
			settings := tc.settings(t, fx)
			_, err := fx.dmsMgr.Service.UpdateDMS(ctx, services.UpdateDMSInput{
				ID:       fx.dms.ID,
				Name:     fx.dms.Name,
				Metadata: fx.dms.Metadata,
				Settings: &settings,
			})
			require.ErrorIs(t, err, errs.ErrValidateBadRequest)
			require.ErrorIs(t, err, errs.ErrDMSIssuanceProfileOverridesCN)
		})
	}
}

// A profile that does not honor the subject but leaves the CommonName empty keeps the CSR CommonName.
func TestSaveDMSAcceptsIssuanceProfileKeepingCN(t *testing.T) {
	ctx := context.Background()
	fx := newEnrollBindFixture(t)

	p := models.IssuanceProfile{
		Validity:     fx.profile.Validity,
		HonorSubject: false,
		Subject:      models.Subject{Organization: "ACME", Country: "ES"},
	}
	settings := fx.dms.Settings
	settings.IssuanceProfile = &p

	_, err := fx.dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       uuid.NewV7().String(),
		Name:     "TestDMS",
		Metadata: map[string]any{},
		Settings: settings,
	})
	require.NoError(t, err)
}

// The profile can change after the DMS is saved, so enrollment checks it again before signing.
func TestEnrollRejectsIssuanceProfileOverridingCN(t *testing.T) {
	ctx := context.Background()
	fx := newEnrollBindFixture(t)
	overrideFixtureProfileCN(t, fx)

	deviceID := fmt.Sprintf("device-%s", uuid.NewV7().String())
	key, _ := chelpers.GenerateECDSAKey(elliptic.P224())
	csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, key)

	issuedBefore := countCertificatesIssuedBy(t, fx, fx.enrollCA.ID)
	_, err := fx.estCli.Enroll(ctx, csr)
	require.Error(t, err, "enrollment should be rejected")
	assert.Equal(t, issuedBefore, countCertificatesIssuedBy(t, fx, fx.enrollCA.ID), "no certificate should be issued")

	// The DMS registers devices just in time, but a rejected enrollment must not leave a device behind.
	_, err = fx.testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: deviceID})
	assert.ErrorIs(t, err, errs.ErrDeviceNotFound, "no device should be registered")
}

func TestReenrollRejectsIssuanceProfileOverridingCN(t *testing.T) {
	ctx := context.Background()
	fx := newEnrollBindFixture(t)

	deviceID := fmt.Sprintf("device-%s", uuid.NewV7().String())
	key, _ := chelpers.GenerateECDSAKey(elliptic.P224())
	csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, key)
	crt, err := fx.estCli.Enroll(ctx, csr)
	require.NoError(t, err, "first enrollment should succeed")

	overrideFixtureProfileCN(t, fx)

	reenrollCli := est.Client{
		Host:                  fx.estCli.Host,
		AdditionalPathSegment: fx.dms.ID,
		Certificates:          []*x509.Certificate{crt},
		PrivateKey:            key,
		InsecureSkipVerify:    true,
	}
	issuedBefore := countCertificatesIssuedBy(t, fx, fx.enrollCA.ID)
	_, err = reenrollCli.Reenroll(ctx, csr)
	require.Error(t, err, "reenrollment should be rejected")
	assert.Equal(t, issuedBefore, countCertificatesIssuedBy(t, fx, fx.enrollCA.ID), "no certificate should be issued")
}
