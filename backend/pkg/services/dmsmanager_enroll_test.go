package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
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

// enrollDevice builds a device of the DMS. serial is the active certificate of its identity ("" for no identity).
func enrollDevice(status models.DeviceStatus, serial string) *models.Device {
	d := &models.Device{ID: enrollDeviceID, DMSOwner: enrollDMSID, Status: status}
	if serial != "" {
		d.IdentitySlot = &models.Slot[string]{Status: models.SlotActive, Secrets: map[int]string{0: serial}}
	}
	return d
}

// enrolledDevice is the device as stored after binding newSerial on top of the previous identity.
func enrolledDevice(previousSerial string, newSerial string) *models.Device {
	d := enrollDevice(models.DeviceActive, previousSerial)
	if d.IdentitySlot == nil {
		d.IdentitySlot = &models.Slot[string]{Status: models.SlotActive, Secrets: map[int]string{0: newSerial}}
		return d
	}
	d.IdentitySlot.ActiveVersion = 1
	d.IdentitySlot.Secrets[1] = newSerial
	return d
}

// readsDevices makes GetDeviceByID return the given devices in order: the one Enroll reads first, and the one it
// reads again after binding.
func (fx *enrollFixture) readsDevices(devices ...*models.Device) {
	for _, d := range devices {
		fx.dev.On("GetDeviceByID", mock.Anything, services.GetDeviceByIDInput{ID: enrollDeviceID}).Return(d, nil).Once()
	}
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

func (fx *enrollFixture) revokes(serial string, reason models.RevocationReason) *mock.Call {
	return fx.ca.On("UpdateCertificateStatus", mock.Anything, services.UpdateCertificateStatusInput{
		SerialNumber:     serial,
		NewStatus:        models.StatusRevoked,
		RevocationReason: reason,
	}).Return(&models.Certificate{}, nil)
}

func (fx *enrollFixture) enroll() (*x509.Certificate, error) {
	return fx.svc.Enroll(context.Background(), fx.csr, enrollDMSID)
}

func TestEnrollDeviceWithoutIdentityIsFirstEnrollment(t *testing.T) {
	for _, replaceable := range []bool{false, true} {
		t.Run(map[bool]string{false: "replaceable off", true: "replaceable on"}[replaceable], func(t *testing.T) {
			fx := newEnrollFixture(t, replaceable)
			fx.readsDevices(enrollDevice(models.DeviceNoIdentity, ""), enrolledDevice("", enrollNewSerial))
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
		fx.readsDevices(enrollDevice(models.DeviceActive, enrollOldSerial))

		_, err := fx.enroll()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "forbiddenNewEnrollment")
		fx.ca.AssertNotCalled(t, "SignCertificate", mock.Anything, mock.Anything)
	})

	t.Run("replaceable on replaces the identity and revokes the previous certificate", func(t *testing.T) {
		fx := newEnrollFixture(t, true)
		fx.readsDevices(enrollDevice(models.DeviceActive, enrollOldSerial), enrolledDevice(enrollOldSerial, enrollNewSerial))
		fx.signs()
		fx.binds(models.DeviceEventTypeReProvisioned)
		fx.revokes(enrollOldSerial, ocsp.Superseded)

		_, err := fx.enroll()

		require.NoError(t, err)
		fx.ca.AssertExpectations(t)
		fx.ca.AssertNotCalled(t, "UpdateCertificateStatus", mock.Anything, services.UpdateCertificateStatusInput{
			SerialNumber: enrollNewSerial, NewStatus: models.StatusRevoked, RevocationReason: ocsp.CessationOfOperation,
		})
	})
}

func TestEnrollRejectsDecommissionedDeviceBeforeSigning(t *testing.T) {
	for _, replaceable := range []bool{false, true} {
		t.Run(map[bool]string{false: "replaceable off", true: "replaceable on"}[replaceable], func(t *testing.T) {
			fx := newEnrollFixture(t, replaceable)
			fx.readsDevices(enrollDevice(models.DeviceDecommissioned, ""))

			_, err := fx.enroll()

			require.Error(t, err)
			assert.Contains(t, err.Error(), "device decommissioned")
			fx.ca.AssertNotCalled(t, "SignCertificate", mock.Anything, mock.Anything)
			fx.dms.AssertNotCalled(t, "BindIdentityToDevice", mock.Anything, mock.Anything)
		})
	}
}

// The checks before the CA signs read the device once. These tests change what the device looks like afterwards,
// which is what a decommission or another enrollment of the same device does while the CA is signing.
func TestEnrollRevokesTheCertificateItCouldNotBind(t *testing.T) {
	t.Run("binding fails", func(t *testing.T) {
		fx := newEnrollFixture(t, false)
		fx.readsDevices(enrollDevice(models.DeviceNoIdentity, ""))
		fx.signs()
		fx.dms.On("BindIdentityToDevice", mock.Anything, mock.Anything).Return((*models.BindIdentityToDeviceOutput)(nil), errors.New("boom"))
		fx.revokes(enrollNewSerial, ocsp.CessationOfOperation)

		crt, err := fx.enroll()

		require.EqualError(t, err, "boom")
		assert.Nil(t, crt)
		fx.ca.AssertExpectations(t)
	})

	t.Run("device is decommissioned while the CA signs", func(t *testing.T) {
		fx := newEnrollFixture(t, false)
		decommissioned := enrollDevice(models.DeviceDecommissioned, "")
		fx.readsDevices(enrollDevice(models.DeviceNoIdentity, ""), decommissioned)
		fx.signs()
		fx.binds(models.DeviceEventTypeProvisioned)
		fx.revokes(enrollNewSerial, ocsp.CessationOfOperation)

		crt, err := fx.enroll()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "device decommissioned")
		assert.Nil(t, crt)
		fx.ca.AssertExpectations(t)
	})

	t.Run("binding reports success but the device keeps no identity", func(t *testing.T) {
		fx := newEnrollFixture(t, false)
		fx.readsDevices(enrollDevice(models.DeviceNoIdentity, ""), enrollDevice(models.DeviceNoIdentity, ""))
		fx.signs()
		fx.binds(models.DeviceEventTypeProvisioned)
		fx.revokes(enrollNewSerial, ocsp.CessationOfOperation)

		_, err := fx.enroll()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not be bound")
		fx.ca.AssertExpectations(t)
	})

	t.Run("another enrollment took the identity of the device", func(t *testing.T) {
		fx := newEnrollFixture(t, false)
		fx.readsDevices(enrollDevice(models.DeviceNoIdentity, ""), enrollDevice(models.DeviceActive, "cc-other"))
		fx.signs()
		fx.binds(models.DeviceEventTypeProvisioned)
		fx.revokes(enrollNewSerial, ocsp.CessationOfOperation)

		_, err := fx.enroll()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not be bound")
		fx.ca.AssertExpectations(t)
		fx.ca.AssertNotCalled(t, "UpdateCertificateStatus", mock.Anything, services.UpdateCertificateStatusInput{
			SerialNumber: "cc-other", NewStatus: models.StatusRevoked, RevocationReason: ocsp.CessationOfOperation,
		})
	})

	t.Run("the original error is returned even if the revocation fails", func(t *testing.T) {
		fx := newEnrollFixture(t, false)
		fx.readsDevices(enrollDevice(models.DeviceNoIdentity, ""), enrollDevice(models.DeviceDecommissioned, ""))
		fx.signs()
		fx.binds(models.DeviceEventTypeProvisioned)
		fx.ca.On("UpdateCertificateStatus", mock.Anything, mock.Anything).Return((*models.Certificate)(nil), errors.New("ca down"))

		_, err := fx.enroll()

		require.Error(t, err)
		assert.Contains(t, err.Error(), "device decommissioned")
		fx.ca.AssertExpectations(t)
	})

	t.Run("a device that cannot be read is not reported as a failure", func(t *testing.T) {
		fx := newEnrollFixture(t, false)
		fx.readsDevices(enrollDevice(models.DeviceNoIdentity, ""))
		fx.dev.On("GetDeviceByID", mock.Anything, services.GetDeviceByIDInput{ID: enrollDeviceID}).Return((*models.Device)(nil), errors.New("db down")).Once()
		fx.signs()
		fx.binds(models.DeviceEventTypeProvisioned)

		crt, err := fx.enroll()

		require.NoError(t, err)
		assert.NotNil(t, crt)
		fx.ca.AssertNotCalled(t, "UpdateCertificateStatus", mock.Anything, mock.Anything)
	})
}

func TestBindIdentityToDeviceRejectsDecommissionedDevice(t *testing.T) {
	fx := newEnrollFixture(t, false)
	fx.ca.On("GetCertificateBySerialNumber", mock.Anything, services.GetCertificatesBySerialNumberInput{SerialNumber: enrollNewSerial}).
		Return(&models.Certificate{SerialNumber: enrollNewSerial}, nil)
	fx.readsDevices(enrollDevice(models.DeviceDecommissioned, ""))

	out, err := fx.svc.BindIdentityToDevice(context.Background(), services.BindIdentityToDeviceInput{
		DeviceID:                enrollDeviceID,
		CertificateSerialNumber: enrollNewSerial,
		BindMode:                models.DeviceEventTypeProvisioned,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "device decommissioned")
	assert.Nil(t, out)
	fx.ca.AssertNotCalled(t, "UpdateCertificateMetadata", mock.Anything, mock.Anything)
	fx.dev.AssertNotCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, mock.Anything)
}
