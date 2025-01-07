package pkg

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
)

type AWSIoTThingConnectionDisconnectionEventHandler struct {
	svc    AWSCloudConnectorService
	logger *logrus.Entry
}

func NewAWSIoTThingConnectionDisconnectionEventHandler(l *logrus.Entry, svc AWSCloudConnectorService) eventhandling.EventHandler {
	evHandler := &AWSIoTThingConnectionDisconnectionEventHandler{
		svc:    svc,
		logger: l,
	}
	return evHandler
}

// Example Connect message: {"event":{"versionNumber":0,"ipAddress":"193.145.247.253","principalIdentifier":"2b167dadf27c505f09b7c66faefba154c7628784b5241f0e165db5991d0904c1","sessionIdentifier":"628de06c-0a13-43ef-9da3-98c16da5150c","eventType":"connected","timestamp":1726138344852,"clientId":"konnektbox_1726138338"},"timestamp":1726138344852,"eventType":"connected","clientId":"konnektbox_1726138338"}
// Example Disconnect message: {"event":{"versionNumber":0,"disconnectReason":"CONNECTION_LOST","principalIdentifier":"8b50adbe78be715d49328433ab4a2306ae1eb496d703851ef17bc2ed4914d4ef","sessionIdentifier":"656a11a8-90f4-47e5-9965-212612ea4787","clientInitiatedDisconnect":false,"eventType":"disconnected","timestamp":1726138599198,"clientId":"konnektbox_1726138529"},"timestamp":1726138599198,"eventType":"disconnected","clientId":"konnektbox_1726138529"}
func (h *AWSIoTThingConnectionDisconnectionEventHandler) HandleMessage(msg *message.Message) error {
	h.logger.Infof("Received event: %s", msg.Payload)

	type connectMsg struct {
		Event struct {
			VersionNumber       int    `json:"versionNumber"`
			IpAddress           string `json:"ipAddress"`
			PrincipalIdentifier string `json:"principalIdentifier"`
			SessionIdentifier   string `json:"sessionIdentifier"`
			EventType           string `json:"eventType"`
			Timestamp           int64  `json:"timestamp"`
			ClientId            string `json:"clientId"`
		} `json:"event"`
		Timestamp int64  `json:"timestamp"`
		EventType string `json:"eventType"`
		ClientId  string `json:"clientId"`
	}

	type disconnectMsg struct {
		Event struct {
			VersionNumber             int    `json:"versionNumber"`
			DisconnectReason          string `json:"disconnectReason"`
			PrincipalIdentifier       string `json:"principalIdentifier"`
			SessionIdentifier         string `json:"sessionIdentifier"`
			ClientInitiatedDisconnect bool   `json:"clientInitiatedDisconnect"`
			EventType                 string `json:"eventType"`
			Timestamp                 int64  `json:"timestamp"`
			ClientId                  string `json:"clientId"`
		} `json:"event"`
		Timestamp int64  `json:"timestamp"`
		EventType string `json:"eventType"`
		ClientId  string `json:"clientId"`
	}

	deviceID := ""
	principalID := ""
	isConnectEvent := false
	var connect connectMsg
	var disconnect disconnectMsg
	//regardless of the message type, we will try to unmarshal it as a connect message since both connect and disconnect messages have the EventType field
	err := json.Unmarshal(msg.Payload, &connect)
	if err != nil {
		h.logger.Errorf("could not unmarshal message: %s", err)
		return err
	}

	if connect.Event.EventType == "connected" {
		h.logger.Debugf("received connect message for device %s", connect.Event.ClientId)
		deviceID = connect.Event.ClientId
		principalID = connect.Event.PrincipalIdentifier
		isConnectEvent = true
	} else {
		deviceID = connect.Event.ClientId
		principalID = connect.Event.PrincipalIdentifier
		isConnectEvent = false
		err = json.Unmarshal(msg.Payload, &disconnect)
		if err != nil {
			h.logger.Errorf("could not unmarshal message: %s", err)
			return err
		}

		h.logger.Debugf("received disconnect message for device %s", deviceID)
	}

	device, err := h.svc.GetDeviceService().GetDeviceByID(context.Background(), services.GetDeviceByIDInput{
		ID: deviceID,
	})
	if err != nil {
		h.logger.Errorf("could not get device %s: %s", deviceID, err)
		// return err
		return nil
	}

	var deviceMetaAWS models.DeviceAWSMetadata
	hasKey, err := helpers.GetMetadataToStruct(device.Metadata, models.AWSIoTMetadataKey(h.svc.GetConnectorID()), &deviceMetaAWS)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.AWSIoTMetadataKey(h.svc.GetConnectorID()), err)
		h.logger.Errorf(err.Error())
		return err
	}

	if !hasKey {
		h.logger.Warnf("device %s does not have metadata for connector %s. IoTCore and Lamassu have the same device ID, metadata was expected", device.ID, h.svc.GetConnectorID())
		//If a device enrolls and connects to IoTCore immediately. Events might not be processed in order and the device might not have metadata yet. Return error to retry the message
		return fmt.Errorf("device %s does not have metadata for connector %s", device.ID, h.svc.GetConnectorID())
	}

	eventDescription := ""
	if isConnectEvent {
		deviceMetaAWS.ConnectionDetails = models.DeviceAWSConnectionDetails{
			IsConnected: true,
			IPAddress:   connect.Event.IpAddress,
			//second to millisecond rounding to 999
			LatestConnectionUpdate: time.Unix(0, connect.Event.Timestamp*int64(time.Millisecond)+999),
		}

		eventDescription = fmt.Sprintf("Device connected from IP %s", connect.Event.IpAddress)
	} else {
		deviceMetaAWS.ConnectionDetails = models.DeviceAWSConnectionDetails{
			IsConnected:            false,
			DisconnectionReason:    disconnect.Event.DisconnectReason,
			LatestConnectionUpdate: time.Unix(0, disconnect.Event.Timestamp*int64(time.Millisecond)+999),
		}

		eventDescription = fmt.Sprintf("Device disconnected with reason %s", disconnect.Event.DisconnectReason)
	}

	newMeta := device.Metadata
	newMeta[models.AWSIoTMetadataKey(h.svc.GetConnectorID())] = deviceMetaAWS

	_, err = h.svc.GetDeviceService().UpdateDeviceMetadata(context.Background(), services.UpdateDeviceMetadataInput{
		ID:       device.ID,
		Metadata: newMeta,
	})
	if err != nil {
		h.logger.Errorf("could not update device metadata: %s", err)
		return err
	}

	h.logger.Infof("updated device %s metadata", device.ID)

	_, err = h.svc.GetDeviceService().CreateDeviceEvent(context.Background(), services.CreateDeviceEventInput{
		DeviceID:    device.ID,
		Timestamp:   deviceMetaAWS.ConnectionDetails.LatestConnectionUpdate,
		Type:        models.DeviceEventTypeConnectionUpdate,
		Description: eventDescription,
		Source:      models.AWSIoTSource(h.svc.GetConnectorID()),
		StructuredFields: map[string]any{
			"principal_identifier": principalID,
		},
	})
	if err != nil {
		h.logger.Errorf("could not create device event: %s", err)
		return err
	}

	return nil
}

type AWSIoTThingShadowUpdateEventHandler struct {
	svc    AWSCloudConnectorService
	logger *logrus.Entry
}

func NewAWSIoTThingShadowUpdateEventHandler(l *logrus.Entry, svc AWSCloudConnectorService) eventhandling.EventHandler {
	evHandler := &AWSIoTThingShadowUpdateEventHandler{
		svc:    svc,
		logger: l,
	}
	return evHandler
}

// Example: {"previous":{"state":{"desired":{"identity_actions":{"UPDATE_TRUST_ANCHOR_LIST":1726231546467}}},"metadata":{"desired":{"identity_actions":{"UPDATE_TRUST_ANCHOR_LIST":{"timestamp":1726231546}}}},"version":1},"current":{"state":{"desired":{"identity_actions":{"UPDATE_TRUST_ANCHOR_LIST":1726231546467}},"reported":{"identity_actions":{"UPDATE_TRUST_ANCHOR_LIST":1726231546467}}},"metadata":{"desired":{"identity_actions":{"UPDATE_TRUST_ANCHOR_LIST":{"timestamp":1726231546}}},"reported":{"identity_actions":{"UPDATE_TRUST_ANCHOR_LIST":{"timestamp":1726231546}}}},"version":2},"timestamp":1726231546}
func (h *AWSIoTThingShadowUpdateEventHandler) HandleMessage(msg *message.Message) error {
	h.logger.Infof("Received event: %s", msg.Payload)

	type shadowState struct {
		Desired  map[string]any `json:"desired"`
		Reported map[string]any `json:"reported"`
	}

	type shadowMetadata struct {
		Desired  map[string]any `json:"desired"`
		Reported map[string]any `json:"reported"`
	}

	type shadowUpdateMsg struct {
		Event struct {
			Previous struct {
				State    shadowState    `json:"state"`
				Metadata shadowMetadata `json:"metadata"`
				Version  int            `json:"version"`
			} `json:"previous"`
			Current struct {
				State    shadowState    `json:"state"`
				Metadata shadowMetadata `json:"metadata"`
				Version  int            `json:"version"`
			} `json:"current"`
			Timestamp int64 `json:"timestamp"`
		} `json:"event"`
		ClientID string `json:"clientId"`
	}

	var shadowUpdate shadowUpdateMsg
	err := json.Unmarshal(msg.Payload, &shadowUpdate)
	if err != nil {
		h.logger.Errorf("could not unmarshal message: %s", err)
		return err
	}

	//if previous is nil, this is the first shadow update for the device. We can skip the event
	if shadowUpdate.Event.Previous.State.Desired == nil {
		h.logger.Warnf("shadow update message does not contain previous state. skipping event")
		return nil
	}

	//check if Desired and Reported contain the identity_actions key
	_, hasDesiredIdentityActions := shadowUpdate.Event.Current.State.Desired["identity_actions"]
	_, hasReportedIdentityActions := shadowUpdate.Event.Current.State.Reported["identity_actions"]
	if !hasDesiredIdentityActions || !hasReportedIdentityActions {
		h.logger.Warnf("shadow update message does not contain identity_actions key. skipping event")
		return nil
	}

	//parse identity_actions into proper struct
	parser := func(data map[string]any) (map[string]int, error) {
		b, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		var identityActions map[string]int
		err = json.Unmarshal(b, &identityActions)
		if err != nil {
			return nil, err
		}

		return identityActions, nil
	}

	currentReportedIdentityActions, err := parser(shadowUpdate.Event.Current.State.Reported["identity_actions"].(map[string]any))
	if err != nil {
		h.logger.Errorf("could not parse reported identity actions: %s", err)
		return err
	}

	currentDesiredIdentityActions, err := parser(shadowUpdate.Event.Current.State.Desired["identity_actions"].(map[string]any))
	if err != nil {
		h.logger.Errorf("could not parse desired identity actions: %s", err)
		return err
	}

	// If nil, the device has never reported its shadow state before, hence confirm Current desired vs reported and treat as a change
	if shadowUpdate.Event.Previous.State.Reported == nil {
		for action, timestamp := range currentReportedIdentityActions {
			if currentDesiredIdentityActions[action] != timestamp {
				h.logger.Warnf("identity action %s is not the same in desired and reported state. Skipping", action)
				continue
			}

			//Get the time of the change
			timestampTime := time.Unix(0, int64(timestamp)*int64(time.Millisecond))
			timestampTime = timestampTime.Add(time.Millisecond * 999)

			//Create the event
			_, err = h.svc.GetDeviceService().CreateDeviceEvent(context.Background(), services.CreateDeviceEventInput{
				DeviceID:    shadowUpdate.ClientID,
				Timestamp:   timestampTime,
				Type:        models.DeviceEventTypeShadowUpdated,
				Description: fmt.Sprintf("Device ACK: Identity action %s has changed", action),
				Source:      models.AWSIoTSource(h.svc.GetConnectorID()),
			})
			if err != nil {
				h.logger.Errorf("could not create device event: %s", err)
				return err
			}
		}
	} else {
		prevReportedIdentityActions, err := parser(shadowUpdate.Event.Previous.State.Reported["identity_actions"].(map[string]any))
		if err != nil {
			h.logger.Errorf("could not parse previous reported identity actions: %s", err)
			return err
		}

		//check if there is a change in identity actions between the previous and current shadow state (only desired state is checked)
		//if there is no change, we can skip the event
		for action, timestamp := range prevReportedIdentityActions {
			if currentReportedIdentityActions[action] == timestamp {
				h.logger.Debugf("identity action %s has not changed in desired state", action)
				continue
			}

			h.logger.Infof("identity action %s has changed in desired state", action)

			//Get the time of the change
			timestamp := shadowUpdate.Event.Previous.Metadata.Reported["identity_actions"].(map[string]any)[action]

			//parse the timestamp to time.Time
			timestampInt, ok := timestamp.(int)
			if !ok {
				h.logger.Warnf("could not parse timestamp to int")
				continue
			}

			timestampTime := time.Unix(0, int64(timestampInt)*int64(time.Millisecond))

			//Create the event
			_, err = h.svc.GetDeviceService().CreateDeviceEvent(context.Background(), services.CreateDeviceEventInput{
				DeviceID:    shadowUpdate.ClientID,
				Timestamp:   timestampTime,
				Type:        models.DeviceEventTypeShadowUpdated,
				Description: fmt.Sprintf("Device ACK: Identity action %s has changed", action),
				Source:      models.AWSIoTSource(h.svc.GetConnectorID()),
				StructuredFields: map[string]interface{}{
					"shadow_version": shadowUpdate.Event.Previous.Version,
				},
			})
			if err != nil {
				h.logger.Errorf("could not create device event: %s", err)
				return err
			}
		}

	}

	return nil
}
