package handlers

import (
	"context"
	"fmt"
	"slices"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
)

func NewDeviceEventHandler(l *logrus.Entry, svc services.DeviceManagerService) *eventhandling.CloudEventHandler {
	return &eventhandling.CloudEventHandler{
		Logger: l,
		DispatchMap: map[string]func(context.Context, *event.Event) error{
			string(models.EventUpdateCertificateMetadataKey): func(ctx context.Context, m *event.Event) error { return updateCertMetaHandler(ctx, m, svc, l) },
			string(models.EventUpdateCertificateStatusKey):   func(ctx context.Context, m *event.Event) error { return updateCertStatusHandler(ctx, m, svc, l) },
		},
	}
}

func updateCertStatusHandler(ctx context.Context, event *event.Event, svc services.DeviceManagerService, lMessaging *logrus.Entry) error {
	cert, err := chelpers.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	deviceID := cert.Updated.Certificate.Subject.CommonName
	dev, err := svc.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: deviceID,
	})
	if err != nil {
		err = fmt.Errorf("could not get device %s: %s", deviceID, err)
		lMessaging.Error(err)
		return err
	}

	// Decommissioning revokes the certificate, and that revocation lands here: a retired device has no slot to sync.
	if dev.Status == models.DeviceDecommissioned {
		lMessaging.Debugf("skipping event %s, device %s is decommissioned", event.Type(), deviceID)
		return nil
	}

	var attachedBy models.CAAttachedToDevice
	hasKey, err := helpers.GetMetadataToStruct(cert.Updated.Metadata, models.DMSAttachedToDeviceKey, &attachedBy)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.DMSAttachedToDeviceKey, err)
		lMessaging.Error(err)
		return err
	}

	if !hasKey {
		lMessaging.Tracef("skipping event %s, Certificate doesn't have %s key", event.Type(), models.DMSAttachedToDeviceKey)
		return nil
	}

	if dev.IdentitySlot == nil || dev.IdentitySlot.Secrets[dev.IdentitySlot.ActiveVersion] != cert.Updated.SerialNumber {
		//no identity slot, or the event is not for the active certificate. Skip
		return nil
	}

	updated := false
	if cert.Updated.Status == models.StatusExpired {
		updated = true
		dev.IdentitySlot.Status = models.SlotExpired
	}

	if cert.Updated.Status == models.StatusRevoked {
		updated = true
		dev.IdentitySlot.Status = models.SlotRevoke
	}

	//This should be the case when the certificate is un-revoked/reinstated (from the OnHold revocation reason). Its
	//expiration deltas stay triggered, and the monitoring never reports them again: restore the status they reached.
	if cert.Updated.Status == models.StatusActive {
		updated = true
		dev.IdentitySlot.Status = slotStatusFromDeltas(cert.Updated, lMessaging)
	}

	if updated {
		_, err = svc.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{
			ID:                    deviceID,
			Slot:                  *dev.IdentitySlot,
			SyncCertificateStatus: true,
		})
		if err != nil {
			err = fmt.Errorf("could not update ID slot to %s for device %s: %s", dev.IdentitySlot.Status, deviceID, err)
			lMessaging.Error(err)
			return err
		}
	}
	return nil
}

func updateCertMetaHandler(ctx context.Context, event *event.Event, svc services.DeviceManagerService, lMessaging *logrus.Entry) error {
	certUpdate, err := chelpers.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	deviceID := certUpdate.Updated.Subject.CommonName
	dev, err := svc.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: deviceID,
	})
	if err != nil {
		err = fmt.Errorf("could not get device %s: %s", deviceID, err)
		lMessaging.Error(err)
		return err
	}

	if dev.Status == models.DeviceDecommissioned {
		lMessaging.Debugf("skipping event %s, device %s is decommissioned", event.Type(), deviceID)
		return nil
	}

	if dev.IdentitySlot != nil && dev.IdentitySlot.Secrets[dev.IdentitySlot.ActiveVersion] != certUpdate.Updated.SerialNumber {
		//event is not for the active certificate. Skip
		return nil
	}

	if dev.IdentitySlot == nil {
		return nil
	}

	// Act only when a delta triggers. Several can trigger in the same update (the monitoring skips certificates on hold,
	// and its period may be longer than the gap between deltas): the slot takes the most severe status they reach.
	newlyTriggered := func(key string) bool {
		return deltaTriggered(certUpdate.Updated, key, lMessaging) && !deltaTriggered(certUpdate.Previous, key, lMessaging)
	}
	if !newlyTriggered(criticalDelta) && !newlyTriggered(preventiveDelta) {
		return nil
	}

	newStatus := slotStatusFromDeltas(certUpdate.Updated, lMessaging)
	if dev.IdentitySlot.Status == newStatus {
		return nil
	}

	dev.IdentitySlot.Status = newStatus
	_, err = svc.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{
		ID:   deviceID,
		Slot: *dev.IdentitySlot,
	})
	if err != nil {
		err = fmt.Errorf("could not update ID slot to %s for device %s: %s", newStatus, deviceID, err)
		lMessaging.Error(err)
		return err
	}

	return nil
}

// Names of the expiration deltas that the DMS sets on the certificates it binds to devices.
const (
	preventiveDelta = "Preventive"
	criticalDelta   = "Critical"
)

// deltaTriggered reports whether the expiration delta key of the certificate is triggered.
func deltaTriggered(crt models.Certificate, key string, lMessaging *logrus.Entry) bool {
	var deltas models.CAMetadataMonitoringExpirationDeltas
	hasKey, err := helpers.GetMetadataToStruct(crt.Metadata, models.CAMetadataMonitoringExpirationDeltasKey, &deltas)
	if err != nil {
		lMessaging.Errorf("could not decode metadata with key %s: %s", models.CAMetadataMonitoringExpirationDeltasKey, err)
		return false
	}

	if !hasKey {
		return false
	}

	return slices.ContainsFunc(deltas, func(med models.MonitoringExpirationDelta) bool {
		return med.Name == key && med.Triggered
	})
}

// slotStatusFromDeltas returns the status of the identity slot of an active certificate: the most severe one its
// triggered expiration deltas reach.
func slotStatusFromDeltas(crt models.Certificate, lMessaging *logrus.Entry) models.SlotStatus {
	switch {
	case deltaTriggered(crt, criticalDelta, lMessaging):
		return models.SlotAboutToExpire
	case deltaTriggered(crt, preventiveDelta, lMessaging):
		return models.SlotRenewalWindow
	default:
		return models.SlotActive
	}
}
