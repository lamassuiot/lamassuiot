package main

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

func main() {

	// NEW MODELS
	DeviceEventTableName := "device_events"
	type DeviceEvent struct {
		ID               string         `json:"id" gorm:"primaryKey"`
		DeviceID         string         `json:"device_id"`
		Timestamp        time.Time      `json:"timestamp"`
		Type             string         `json:"type"`
		Description      string         `json:"description"`
		Source           string         `json:"source"`
		Status           string         `json:"status"`
		StructuredFields map[string]any `json:"structured_fields" gorm:"serializer:json"`
	}

	// OLD MODELS
	DeviceTableName := "devices"
	type OldDeviceEvent struct {
		EvenType          string `json:"type"`
		EventDescriptions string `json:"description"`
	}

	type Slot[E any] struct {
		Status        string                       `json:"status"`
		ActiveVersion int                          `json:"active_version"`
		SecretType    string                       `json:"type"`
		Secrets       map[int]E                    `json:"versions"` // version -> secret
		Events        map[time.Time]OldDeviceEvent `json:"events" gorm:"serializer:json"`
	}

	type Device struct {
		ID                string                       `json:"id" gorm:"primaryKey"`
		Tags              []string                     `json:"tags" gorm:"serializer:json"`
		Status            string                       `json:"status"`
		Icon              string                       `json:"icon"`
		IconColor         string                       `json:"icon_color"`
		CreationTimestamp time.Time                    `json:"creation_timestamp"`
		Metadata          map[string]any               `json:"metadata" gorm:"serializer:json"`
		DMSOwner          string                       `json:"dms_owner"`
		IdentitySlot      *Slot[string]                `json:"identity,omitempty" gorm:"serializer:json"`
		ExtraSlots        map[string]*Slot[any]        `json:"slots" gorm:"serializer:json"`
		Events            map[time.Time]OldDeviceEvent `json:"events" gorm:"serializer:json"`
	}

	//Sources

	const CASource = "lrn://service/lamassuiot-ca"
	const DMSManagerSource = "lrn://service/lamassuiot-ra"
	const DeviceManagerSource = "lrn://service/lamassuiot-devmanager"
	const VASource = "lrn://service/lamassuiot-va"
	const AlertsSource = "lrn://service/lamassuiot-alerts"
	AWSIoTSource := func(id string) string { return fmt.Sprintf("lrn://service/lamassuiot-awsiot/%s", id) }

	// DeviceEventTypeCreated              DeviceEventType = "CREATED"
	// DeviceEventTypeProvisioned          DeviceEventType = "PROVISIONED"
	// DeviceEventTypeReProvisioned        DeviceEventType = "RE-PROVISIONED"
	// DeviceEventTypeRenewed              DeviceEventType = "RENEWED"
	// DeviceEventTypeShadowUpdated        DeviceEventType = "SHADOW-UPDATED"
	// DeviceEventTypeConnectionUpdate     DeviceEventType = "CONNECTION-UPDATED"
	// DeviceEventTypeStatusUpdated        DeviceEventType = "STATUS-UPDATED"
	// DeviceEventTypeStatusDecommissioned DeviceEventType = "DECOMMISSIONED"

	// TRANSFORM MODELS
	// From a Device object to a DeviceEvent object
	transform := func(device Device) []DeviceEvent {
		events := []DeviceEvent{}
		eventsToProcess := map[time.Time]OldDeviceEvent{}

		for ts, oldEvent := range device.Events {
			eventsToProcess[ts] = oldEvent
		}

		for oldEventTS, oldEvent := range device.IdentitySlot.Events {
			eventsToProcess[oldEventTS] = oldEvent
		}

		//Some events releated with AWS Connector require the connector ID to be get and set. Retrieve one connector ID.

		for oldEventTS, oldEvent := range eventsToProcess {
			// Base event. Some fields will be changed based on the event
			event := DeviceEvent{
				DeviceID:         device.ID,
				Timestamp:        oldEventTS,
				Type:             oldEvent.EvenType,
				Description:      oldEvent.EventDescriptions,
				Source:           "",
				Status:           device.Status,
				StructuredFields: map[string]any{},
				ID:               uuid.NewString(),
			}

			switch oldEvent.EvenType {
			case "CREATED":
				event.Source = DeviceManagerSource
				event.Status = "NO_IDENTITY"
			case "DECOMMISSIONED":
				event.Source = DeviceManagerSource
				event.Description = fmt.Sprintf("Status updated from <unknown> to 'DECOMMISSIONED'", device.Status) // We don't have the old status
			case "STATUS-UPDATED":
				event.Source = DeviceManagerSource
			case "PROVISIONED":
				event.Source = DeviceManagerSource
			case "SHADOW-UPDATED":
				event.Source = AWSIoTSource()

			}

			events = append(events, event)
		}
	}
	return events

	// MIGRATION SCRIPT

}
