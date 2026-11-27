package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

const (
	enrollDMSID     = "dms-1"
	enrollDeviceID  = "dev-1"
	enrollOldSerial = "aa-old"
	enrollNewSerial = "bb-new"
)

type enrollFixture struct {
	svc DMSManagerServiceBackend
	dms *svcmock.MockDMSManagerService
	dev *svcmock.MockDeviceManagerService
	ca  *svcmock.MockCAService
	csr *x509.CertificateRequest
}

func newEnrollFixture(t *testing.T, replaceable bool) *enrollFixture {
	t.Helper()

	fx := &enrollFixture{
		dms: new(svcmock.MockDMSManagerService),
		dev: new(svcmock.MockDeviceManagerService),
		ca:  new(svcmock.MockCAService),
	}

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	fx.svc = DMSManagerServiceBackend{
		service:          fx.dms,
		deviceManagerCli: fx.dev,
		caClient:         fx.ca,
		logger:           logrus.NewEntry(logger),
	}

	fx.dms.On("GetDMSByID", mock.Anything, services.GetDMSByIDInput{ID: enrollDMSID}).Return(&models.DMS{
		ID: enrollDMSID,
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol:          models.EST,
				EnrollmentCA:                "enroll-ca",
				EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{AuthMode: models.ESTAuthModeNoAuth},
				RegistrationMode:            models.PreRegistration,
				EnableReplaceableEnrollment: replaceable,
				VerifyCSRSignature:          true,
			},
			IssuanceProfile: &models.IssuanceProfile{},
		},
	}, nil)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: enrollDeviceID}}, key)
	require.NoError(t, err)
	fx.csr, err = x509.ParseCertificateRequest(der)
	require.NoError(t, err)

	return fx
}

// readsDevice makes GetDeviceByID return a device of the DMS. serial is the active certificate of its identity ("" for
// no identity).
func (fx *enrollFixture) readsDevice(status models.DeviceStatus, serial string) {
	d := &models.Device{ID: enrollDeviceID, DMSOwner: enrollDMSID, Status: status}
	if serial != "" {
		d.IdentitySlot = &models.Slot[string]{Status: models.SlotActive, Secrets: map[int]string{0: serial}}
	}
	fx.dev.On("GetDeviceByID", mock.Anything, services.GetDeviceByIDInput{ID: enrollDeviceID}).Return(d, nil)
}

func (fx *enrollFixture) signs() {
	fx.ca.On("SignCertificate", mock.Anything, mock.Anything).Return(&models.Certificate{
		SerialNumber: enrollNewSerial,
		Certificate:  (*models.X509Certificate)(&x509.Certificate{}),
	}, nil)
}

func (fx *enrollFixture) binds(mode models.DeviceEventType) {
	fx.dms.On("BindIdentityToDevice", mock.Anything, services.BindIdentityToDeviceInput{
		DeviceID:                enrollDeviceID,
		CertificateSerialNumber: enrollNewSerial,
		BindMode:                mode,
	}).Return(&models.BindIdentityToDeviceOutput{}, nil)
}

func (fx *enrollFixture) enroll() (*x509.Certificate, error) {
	return fx.svc.Enroll(context.Background(), fx.csr, enrollDMSID)
}

func TestEnrollDeviceWithoutIdentityIsFirstEnrollment(t *testing.T) {
	for _, replaceable := range []bool{false, true} {
		t.Run(map[bool]string{false: "replaceable off", true: "replaceable on"}[replaceable], func(t *testing.T) {
			fx := newEnrollFixture(t, replaceable)
			fx.readsDevice(models.DeviceNoIdentity, "")
			fx.signs()
			fx.binds(models.DeviceEventTypeProvisioned)

			crt, err := fx.enroll()

			require.NoError(t, err)
			assert.NotNil(t, crt)
			fx.ca.AssertNotCalled(t, "UpdateCertificateStatus", mock.Anything, mock.Anything)
			fx.dms.AssertExpectations(t)
		})
	}
}

func TestEnrollDeviceWithIdentity(t *testing.T) {
	t.Run("replaceable off is refused before signing", func(t *testing.T) {
		fx := newEnrollFixture(t, false)
		fx.readsDevice(models.DeviceActive, enrollOldSerial)

		_, err := fx.enroll()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "forbiddenNewEnrollment")
		fx.ca.AssertNotCalled(t, "SignCertificate", mock.Anything, mock.Anything)
	})

	t.Run("replaceable on replaces the identity and revokes the previous certificate", func(t *testing.T) {
		fx := newEnrollFixture(t, true)
		fx.readsDevice(models.DeviceActive, enrollOldSerial)
		fx.signs()
		fx.binds(models.DeviceEventTypeReProvisioned)
		fx.ca.On("UpdateCertificateStatus", mock.Anything, services.UpdateCertificateStatusInput{
			SerialNumber:     enrollOldSerial,
			NewStatus:        models.StatusRevoked,
			RevocationReason: ocsp.Superseded,
		}).Return(&models.Certificate{}, nil)

		_, err := fx.enroll()

		require.NoError(t, err)
		fx.ca.AssertExpectations(t)
	})
}

func TestEnrollRejectsDecommissionedDeviceBeforeSigning(t *testing.T) {
	for _, replaceable := range []bool{false, true} {
		t.Run(map[bool]string{false: "replaceable off", true: "replaceable on"}[replaceable], func(t *testing.T) {
			fx := newEnrollFixture(t, replaceable)
			fx.readsDevice(models.DeviceDecommissioned, "")

			_, err := fx.enroll()

			require.Error(t, err)
			assert.Contains(t, err.Error(), "device decommissioned")
			fx.ca.AssertNotCalled(t, "SignCertificate", mock.Anything, mock.Anything)
			fx.dms.AssertNotCalled(t, "BindIdentityToDevice", mock.Anything, mock.Anything)
		})
	}
}
