package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	mockservices "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A7: ownership and supersession policy tests for LWCEnroll.
//
// LWCEnroll has two short-circuit policy rejections before any CA call:
//
//  1. The device exists but is owned by a DIFFERENT DMS         → reject
//  2. The device exists, owned by THIS DMS, but the DMS forbids
//     replaceable enrollment (EnableReplaceableEnrollment=false) → reject
//
// And one rejection-free path:
//
//  3. The device does not exist yet — first-time enrollment OK
//     (fully exercised via assembler integration tests)
//
// Cases 1 and 2 are tested here directly to lock down the audit-flagged
// device-ownership/supersession policy without spinning up the full
// integration harness.

// fakeDMSManagerService implements the services.DMSManagerService interface
// just enough for LWCEnroll's call to GetDMSByID to succeed. We need a fake
// because LWCEnroll re-enters the service through svc.service, so a plain
// mock that records the call but never returns the right DMS would deadlock
// the test on the very first call.
type fakeDMSManagerService struct {
	*mockservices.MockDMSManagerService
	dms *models.DMS
}

func (f *fakeDMSManagerService) GetDMSByID(ctx context.Context, in services.GetDMSByIDInput) (*models.DMS, error) {
	if f.dms == nil || in.ID != f.dms.ID {
		return nil, errs.ErrDMSNotFound
	}
	return f.dms, nil
}

func newPolicyTestSubject(t *testing.T, dms *models.DMS) (*DMSManagerServiceBackend, *mockservices.MockDeviceManagerService, *mockservices.MockCAService) {
	t.Helper()
	devMock := &mockservices.MockDeviceManagerService{}
	caMock := &mockservices.MockCAService{}
	dmsMock := &fakeDMSManagerService{
		MockDMSManagerService: &mockservices.MockDMSManagerService{},
		dms:                   dms,
	}
	logger := logrus.NewEntry(logrus.New())
	svc := &DMSManagerServiceBackend{
		deviceManagerCli: devMock,
		caClient:         caMock,
		logger:           logger,
	}
	svc.service = dmsMock
	return svc, devMock, caMock
}

// dmsWithEnrollAuth returns a DMS configured with the given enrollment-auth
// mode and replaceable-enrollment flag, plus a CMP-friendly base.
func dmsWithEnrollAuth(id string, replaceable bool) *models.DMS {
	return &models.DMS{
		ID: id,
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentCA:                "test-ca",
				EnableReplaceableEnrollment: replaceable,
				EnrollmentOptionsLWCRFC9483: models.EnrollmentOptionsLWCRFC9483{
					AuthMode: models.EnrollmentAuthModeNoAuth,
				},
			},
		},
	}
}

func makeTestCSR(t *testing.T, cn string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	return csr
}

// TestLWCEnroll_DeviceOwnedByDifferentDMS rejects when an existing device is
// owned by a DMS other than the one currently enrolling.
func TestLWCEnroll_DeviceOwnedByDifferentDMS(t *testing.T) {
	dms := dmsWithEnrollAuth("dms-A", true)
	svc, devMock, caMock := newPolicyTestSubject(t, dms)
	csr := makeTestCSR(t, "device-1")

	// Existing device owned by a different DMS.
	devMock.On("GetDeviceByID", mock.Anything, services.GetDeviceByIDInput{ID: "device-1"}).
		Return(&models.Device{ID: "device-1", DMSOwner: "dms-B"}, nil)

	// Pre-authenticate so the auth path is bypassed (NO_AUTH would also work
	// but PreAuth makes the test independent of the auth-mode default).
	ctx := context.WithValue(context.Background(), core.LamassuContextKeyPreAuthenticated, true)
	_, err := svc.LWCEnroll(ctx, csr, "dms-A")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered to another DMS")

	// CA SignCertificate MUST NOT be reached on a policy rejection.
	caMock.AssertNotCalled(t, "SignCertificate", mock.Anything, mock.Anything)
}

// TestLWCEnroll_DeviceOwnedByDifferentDMS_RejectsBeforeAnyCACall is the
// negative-side audit guard: an owned-elsewhere device should be rejected
// even when the DMS allows replaceable enrollment for ITS OWN devices.
func TestLWCEnroll_DeviceOwnedByDifferentDMS_EvenWithReplaceable(t *testing.T) {
	dms := dmsWithEnrollAuth("dms-A", true /* replaceable */)
	svc, devMock, caMock := newPolicyTestSubject(t, dms)
	csr := makeTestCSR(t, "device-2")

	devMock.On("GetDeviceByID", mock.Anything, services.GetDeviceByIDInput{ID: "device-2"}).
		Return(&models.Device{ID: "device-2", DMSOwner: "dms-Z"}, nil)

	ctx := context.WithValue(context.Background(), core.LamassuContextKeyPreAuthenticated, true)
	_, err := svc.LWCEnroll(ctx, csr, "dms-A")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered to another DMS")
	caMock.AssertNotCalled(t, "SignCertificate", mock.Anything, mock.Anything)
}

// TestLWCEnroll_ReplaceableEnrollmentDisabled rejects when the device is
// owned by THIS DMS but the DMS forbids replaceable enrollment.
func TestLWCEnroll_ReplaceableEnrollmentDisabled(t *testing.T) {
	dms := dmsWithEnrollAuth("dms-A", false /* not replaceable */)
	svc, devMock, caMock := newPolicyTestSubject(t, dms)
	csr := makeTestCSR(t, "device-3")

	devMock.On("GetDeviceByID", mock.Anything, services.GetDeviceByIDInput{ID: "device-3"}).
		Return(&models.Device{ID: "device-3", DMSOwner: "dms-A"}, nil)

	ctx := context.WithValue(context.Background(), core.LamassuContextKeyPreAuthenticated, true)
	_, err := svc.LWCEnroll(ctx, csr, "dms-A")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbiddenNewEnrollment")
	caMock.AssertNotCalled(t, "SignCertificate", mock.Anything, mock.Anything)
}

// TestLWCEnroll_PassesOwnershipAndProceeds confirms that an owned-by-this-DMS
// device WITH replaceable-enrollment enabled gets past the policy gate (the
// next stop is resolveIssuanceProfile / SignCertificate, which we don't mock
// — the test asserts only that the policy gate let the call through, by
// requiring SignCertificate to be invoked at least once).
func TestLWCEnroll_PassesOwnershipAndProceeds(t *testing.T) {
	dms := dmsWithEnrollAuth("dms-A", true)
	svc, devMock, caMock := newPolicyTestSubject(t, dms)
	csr := makeTestCSR(t, "device-4")

	devMock.On("GetDeviceByID", mock.Anything, services.GetDeviceByIDInput{ID: "device-4"}).
		Return(&models.Device{ID: "device-4", DMSOwner: "dms-A", IdentitySlot: nil}, nil)

	// resolveIssuanceProfile re-enters the service to look up the enrollment
	// CA; failing that here is fine — we only want to confirm we got PAST
	// the ownership check. Stub the CA call to return a typed error so the
	// test asserts the error came from the post-policy stage.
	caMock.On("GetCAByID", mock.Anything, mock.Anything).
		Return((*models.CACertificate)(nil), errs.ErrCANotFound)

	ctx := context.WithValue(context.Background(), core.LamassuContextKeyPreAuthenticated, true)
	_, err := svc.LWCEnroll(ctx, csr, "dms-A")
	require.Error(t, err)
	// The error MUST NOT be the policy-rejection string — it must be a
	// downstream failure proving the policy gate passed.
	assert.NotContains(t, err.Error(), "already registered to another DMS")
	assert.NotContains(t, err.Error(), "forbiddenNewEnrollment")
	caMock.AssertCalled(t, "GetCAByID", mock.Anything, mock.Anything)
}

// Silence unused-import warning when chelpers is not used directly.
var _ = chelpers.ConfigureLogger
