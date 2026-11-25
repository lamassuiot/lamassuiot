package services

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type bindDMSRepo struct {
	storage.DMSRepo
}

func (bindDMSRepo) SelectExists(_ context.Context, id string) (bool, *models.DMS, error) {
	return true, &models.DMS{ID: id}, nil
}

func TestBindIdentityToDeviceRejectsUnconfirmedSlotUpdate(t *testing.T) {
	ctx := context.Background()
	cert := &models.Certificate{SerialNumber: "01"}
	device := &models.Device{ID: "device-1", DMSOwner: "dms-1", Status: models.DeviceNoIdentity}
	decommissioned := *device
	decommissioned.Status = models.DeviceDecommissioned
	previousIdentity := *device
	previousIdentity.Status = models.DeviceActive
	previousIdentity.IdentitySlot = &models.Slot[string]{
		Status:  models.SlotActive,
		Secrets: map[int]string{0: "02"},
	}

	for _, tc := range []struct {
		name    string
		updated *models.Device
	}{
		{name: "decommissioned during binding", updated: &decommissioned},
		{name: "different serial still active", updated: &previousIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := &svcmock.MockCAService{}
			ca.On("GetCertificateBySerialNumber", ctx, coreservices.GetCertificatesBySerialNumberInput{
				SerialNumber: cert.SerialNumber,
			}).Return(cert, nil).Once()
			ca.On("UpdateCertificateMetadata", ctx, mock.Anything).Return(cert, nil).Once()

			devices := &svcmock.MockDeviceManagerService{}
			devices.On("GetDeviceByID", ctx, coreservices.GetDeviceByIDInput{ID: device.ID}).Return(device, nil).Once()
			devices.On("UpdateDeviceIdentitySlot", ctx, mock.Anything).Return(tc.updated, nil).Once()
			devices.On("CreateDeviceEvent", ctx, mock.Anything).Return(&models.DeviceEvent{}, nil).Maybe()

			dms := NewDMSManagerService(DMSManagerBuilder{
				Logger:        logrus.NewEntry(logrus.New()),
				DMSStorage:    bindDMSRepo{},
				CAClient:      ca,
				DevManagerCli: devices,
			})
			result, err := dms.BindIdentityToDevice(ctx, coreservices.BindIdentityToDeviceInput{
				DeviceID:                device.ID,
				CertificateSerialNumber: cert.SerialNumber,
				BindMode:                models.DeviceEventTypeProvisioned,
			})

			assert.Error(t, err)
			assert.Nil(t, result)
			devices.AssertExpectations(t)
			devices.AssertNotCalled(t, "CreateDeviceEvent", mock.Anything, mock.Anything)
		})
	}
}
