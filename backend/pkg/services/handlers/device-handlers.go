package handlers

import (
	"context"
	"fmt"
	"slices"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
)

func NewDeviceEventHandler(l *logrus.Entry, svc services.DeviceManagerService) *eventhandling.CloudEventHandler {
	return &eventhandling.CloudEventHandler{
		Logger: l,
		DispatchMap: map[string]func(*event.Event) error{
			string(models.EventUpdateCertificateMetadataKey): func(m *event.Event) error { return updateCertMetaHandler(m, svc, l) },
			string(models.EventUpdateCertificateStatusKey):   func(m *event.Event) error { return updateCertStatusHandler(m, svc, l) },
		},
	}
}

func updateCertStatusHandler(event *event.Event, svc services.DeviceManagerService, lMessaging *logrus.Entry) error {
	ctx := context.Background()

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

	var attachedBy models.CAAttachedToDevice
	hasKey, err := helpers.GetMetadataToStruct(cert.Updated.Metadata, models.CAAttachedToDeviceKey, &attachedBy)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.CAAttachedToDeviceKey, err)
		lMessaging.Error(err)
		return err
	}

	if !hasKey {
		lMessaging.Tracef("skipping event %s, Certificate doesn't have %s key", event.Type(), models.CAAttachedToDeviceKey)
		return nil
	}

	if dev.IdentitySlot.Secrets[dev.IdentitySlot.ActiveVersion] != cert.Updated.SerialNumber {
		//event is not for the active certificate. Skip
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

	//This should be the case when the certificate is un-revoked/reinstated (from the OnHold revocation reason)
	if cert.Updated.Status == models.StatusActive {
		updated = true
		dev.IdentitySlot.Status = models.SlotActive
	}

	if updated {
		_, err = svc.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{
			ID:   deviceID,
			Slot: *dev.IdentitySlot,
		})
		if err != nil {
			err = fmt.Errorf("could not update ID slot to preventive for device %s: %s", deviceID, err)
			lMessaging.Error(err)
			return err
		}
	}
	return nil
}

func updateCertMetaHandler(event *event.Event, svc services.DeviceManagerService, lMessaging *logrus.Entry) error {
	ctx := context.Background()

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

	if dev.IdentitySlot != nil && dev.IdentitySlot.Secrets[dev.IdentitySlot.ActiveVersion] != certUpdate.Updated.SerialNumber {
		//event is not for the active certificate. Skip
		return nil
	}

	checkIfTriggered := func(crt models.Certificate, key string) bool {
		var deltas models.CAMetadataMonitoringExpirationDeltas
		hasKey, err := helpers.GetMetadataToStruct(crt.Metadata, models.CAMetadataMonitoringExpirationDeltasKey, &deltas)
		if err != nil {
			lMessaging.Errorf("could not decode metadata with key %s: %s", models.CAMetadataMonitoringExpirationDeltasKey, err)
			return false
		}

		if !hasKey {
			return false
		}

		idx := slices.IndexFunc(deltas, func(med models.MonitoringExpirationDelta) bool {
			if med.Name == key && med.Triggered {
				return true
			}
			return false
		})

		return idx != -1
	}

	criticalTriggered := checkIfTriggered(certUpdate.Updated, "Critical")
	if criticalTriggered {
		prevCriticalTriggered := checkIfTriggered(certUpdate.Previous, "Critical")
		if !prevCriticalTriggered {
			//no update
			dev.IdentitySlot.Status = models.SlotAboutToExpire
			_, err = svc.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{
				ID:   deviceID,
				Slot: *dev.IdentitySlot,
			})
			if err != nil {
				err = fmt.Errorf("could not update ID slot to critical for device %s: %s", deviceID, err)
				lMessaging.Error(err)
				return err
			}
		}
	}

	preventiveTriggered := checkIfTriggered(certUpdate.Updated, "Preventive")
	if preventiveTriggered {
		prevPreventiveTriggered := checkIfTriggered(certUpdate.Previous, "Preventive")
		if !prevPreventiveTriggered {
			//no update
			dev.IdentitySlot.Status = models.SlotRenewalWindow
			_, err = svc.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{
				ID:   deviceID,
				Slot: *dev.IdentitySlot,
			})
			if err != nil {
				err = fmt.Errorf("could not update ID slot to preventive for device %s: %s", deviceID, err)
				lMessaging.Error(err)
				return err
			}
		}
	}

	return nil
}
