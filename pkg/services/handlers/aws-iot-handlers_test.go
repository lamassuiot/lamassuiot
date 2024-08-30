package handlers

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	smock "github.com/lamassuiot/lamassuiot/v2/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

// A device certificate is updated and the preventive delta is changed from false to true
// The connector should update the device shadow
func TestHandleUpdateCertificate(t *testing.T) {
	// Prepare logger
	entry := logrus.WithField("svc", "aws-iot")

	eventContent, err := os.ReadFile("testdata/cloudevents/cert_update_status__revoked.json")
	if err != nil {
		t.Error(err)
	}

	message := message.Message{
		Payload: eventContent,
	}

	// Prepare mocks
	awsConnectorMock := smock.MockAWSCloudConnectorService{}
	awsConnectorMock.On("GetConnectorID").Return("aws-12345")
	awsConnectorMock.On("UpdateCertificateStatus", mock.Anything, mock.Anything).Return(nil)

	// Test logic
	handler := NewAWSIoTEventHandler(entry, &awsConnectorMock)
	handler.HandleMessage(&message)

	// Assert
	awsConnectorMock.AssertExpectations(t)
	awsConnectorMock.AssertNumberOfCalls(t, "UpdateCertificateStatus", 1)
}

func TestHandleUpdateCertificateNotAttached(t *testing.T) {
	// Prepare logger
	entry := logrus.WithField("svc", "aws-iot")

	eventContent, err := os.ReadFile("testdata/cloudevents/cert_update_status__revoked.json")
	if err != nil {
		t.Error(err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(eventContent, &parsed)
	data := parsed["data"].(map[string]interface{})
	updated := data["updated"].(map[string]interface{})
	metadata := updated["metadata"].(map[string]interface{})
	delete(metadata, "lamassu.io/iot/aws-12345")

	eventContent, err = json.Marshal(parsed)
	if err != nil {
		t.Error(err)
	}

	message := message.Message{
		Payload: eventContent,
	}

	// Prepare mocks
	awsConnectorMock := smock.MockAWSCloudConnectorService{}
	awsConnectorMock.On("GetConnectorID").Return("aws-12345")

	// Test logic
	handler := NewAWSIoTEventHandler(entry, &awsConnectorMock)
	handler.HandleMessage(&message)

	// Assert
	awsConnectorMock.AssertExpectations(t)
	awsConnectorMock.AssertNotCalled(t, "UpdateCertificateStatus")
}

func TestHandleUpdateCertificateNotSameConnector(t *testing.T) {
	// Prepare logger
	entry := logrus.WithField("svc", "aws-iot")

	eventContent, err := os.ReadFile("testdata/cloudevents/cert_update_status__revoked.json")
	if err != nil {
		t.Error(err)
	}

	message := message.Message{
		Payload: eventContent,
	}

	// Prepare mocks
	awsConnectorMock := smock.MockAWSCloudConnectorService{}
	awsConnectorMock.On("GetConnectorID").Return("aws-12345-other")

	// Test logic
	handler := NewAWSIoTEventHandler(entry, &awsConnectorMock)
	handler.HandleMessage(&message)

	// Assert
	awsConnectorMock.AssertExpectations(t)
	awsConnectorMock.AssertNotCalled(t, "UpdateCertificateStatus")
}

// A device certificate is updated and the preventive delta is changed from false to true
// The connector should update the device shadow
func TestHandleUpdateMetadataUpdateShadow(t *testing.T) {
	// Prepare logger
	entry := logrus.WithField("svc", "aws-iot")

	prevState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": false,
		},
	}

	newState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": true,
		},
	}
	message := prepareMessage(t, "testdata/cloudevents/cert_update_metadata__preventive_delta_false_to_true.json", prevState, newState)
	dms := loadDMSFromFile(t, "testdata/dms-settings.json")

	// Prepare mocks
	awsConnectorMock := smock.MockAWSCloudConnectorService{}
	dmsMock := smock.MockDMSManagerService{}
	awsConnectorMock.On("GetDMSService").Return(&dmsMock)
	awsConnectorMock.On("GetConnectorID").Return("aws-12345")
	awsConnectorMock.On("UpdateDeviceShadow", mock.Anything, mock.Anything).Return(nil)
	dmsMock.On("GetDMSByID", mock.Anything, mock.Anything).Return(&dms, nil)

	// Test logic
	handler := NewAWSIoTEventHandler(entry, &awsConnectorMock)
	handler.HandleMessage(message)

	// Assert
	awsConnectorMock.AssertExpectations(t)
	awsConnectorMock.AssertCalled(t, "UpdateDeviceShadow", mock.Anything, mock.Anything)
}

func prepareMessage(t *testing.T, file string, prevState []map[string]interface{}, newState []map[string]interface{}) *message.Message {
	eventContent, err := os.ReadFile(file)
	if err != nil {
		t.Error(err)
	}

	message := message.Message{
		Payload: eventContent,
	}

	event, err := helpers.ParseCloudEvent(message.Payload)
	if err != nil {
		t.Error(err)
	}

	certUpdate, err := helpers.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		t.Error(err)
	}

	certUpdate.Previous.Metadata["lamassu.io/ca/expiration-deltas"] = prevState
	certUpdate.Updated.Metadata["lamassu.io/ca/expiration-deltas"] = newState

	var eventMap map[string]interface{}
	json.Unmarshal(eventContent, &eventMap)
	eventMap["data"] = certUpdate

	content, err := json.Marshal(eventMap)
	if err != nil {
		t.Error(err)
	}
	message.Payload = content
	return &message
}

// A device certificate is updated and the preventive delta is NOT changed (previous=true, updated=true)
// The connector should NOT update the device shadow
func TestHandleUpdateMetadataNotUpdateShadow(t *testing.T) {
	// Prepare logger
	entry := logrus.WithField("svc", "aws-iot")

	prevState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": true,
		},
	}

	newState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": true,
		},
	}

	message := prepareMessage(t, "testdata/cloudevents/cert_update_metadata__preventive_delta_false_to_true.json", prevState, newState)
	dms := loadDMSFromFile(t, "testdata/dms-settings.json")

	// Prepare mocks
	awsConnectorMock := smock.MockAWSCloudConnectorService{}
	dmsMock := smock.MockDMSManagerService{}
	awsConnectorMock.On("GetDMSService").Return(&dmsMock)
	awsConnectorMock.On("GetConnectorID").Return("aws-12345")
	dmsMock.On("GetDMSByID", mock.Anything, mock.Anything).Return(&dms, nil)

	// Test logic
	handler := NewAWSIoTEventHandler(entry, &awsConnectorMock)
	handler.HandleMessage(message)

	// Assert
	awsConnectorMock.AssertExpectations(t)
	awsConnectorMock.AssertNotCalled(t, "UpdateDeviceShadow", mock.Anything, mock.Anything)
}

// A device certificate metadata is updated twice:
//
//	1- the preventive delta is changed (previous=false, updated=true)
//	2- the preventive delta is unchanged (previous=true, updated=true), but critical delta is changed(previous=false, updated=true)
//
// The connector should update the device shadow only once
func TestHandleUpdateMetadataMultipleUpdates(t *testing.T) {
	// Prepare logger
	entry := logrus.WithField("svc", "aws-iot")

	prevState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": false,
		},
	}

	newState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": true,
		},
	}
	message := prepareMessage(t, "testdata/cloudevents/cert_update_metadata__preventive_delta_false_to_true.json", prevState, newState)
	dms := loadDMSFromFile(t, "testdata/dms-settings.json")

	// Prepare mocks
	awsConnectorMock := smock.MockAWSCloudConnectorService{}
	dmsMock := smock.MockDMSManagerService{}
	awsConnectorMock.On("GetDMSService").Return(&dmsMock)
	awsConnectorMock.On("GetConnectorID").Return("aws-12345")
	awsConnectorMock.On("UpdateDeviceShadow", mock.Anything, mock.Anything).Return(nil)
	dmsMock.On("GetDMSByID", mock.Anything, mock.Anything).Return(&dms, nil)

	// Test logic
	handler := NewAWSIoTEventHandler(entry, &awsConnectorMock)
	handler.HandleMessage(message)

	// Assert
	awsConnectorMock.AssertExpectations(t)
	awsConnectorMock.AssertNumberOfCalls(t, "UpdateDeviceShadow", 1)

	// Prepare second event
	prevState = []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": true,
		},
	}

	newState = []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": true,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": true,
		},
	}
	message = prepareMessage(t, "testdata/cloudevents/cert_update_metadata__preventive_delta_false_to_true.json", prevState, newState)

	// Assert
	awsConnectorMock = smock.MockAWSCloudConnectorService{} // Reset mock
	awsConnectorMock.On("GetDMSService").Return(&dmsMock)
	awsConnectorMock.On("GetConnectorID").Return("aws-12345")

	handler.HandleMessage(message)

	awsConnectorMock.AssertExpectations(t)
	awsConnectorMock.AssertNumberOfCalls(t, "UpdateDeviceShadow", 0)
}

// A device certificate is updated and the preventive delta is changed from false to true
// The connector should NOT update the device shadow since the device's DMS is not configured with the connector,
// hence, the shadow should not be updated
func TestHandleUpdateMetadataDMSNoConfiguredNoUpdateShadow(t *testing.T) {
	// Prepare logger
	entry := logrus.WithField("svc", "aws-iot")

	prevState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": false,
		},
	}

	newState := []map[string]interface{}{
		{
			"delta":     "1w",
			"name":      "Critical",
			"triggered": false,
		},
		{
			"delta":     "1y",
			"name":      "Preventive",
			"triggered": true,
		},
	}
	message := prepareMessage(t, "testdata/cloudevents/cert_update_metadata__preventive_delta_false_to_true.json", prevState, newState)

	// Prepare DMS data
	dms := loadDMSFromFile(t, "testdata/dms-settings.json")
	delete(dms.Metadata, "lamassu.io/iot/aws-12345")

	// Prepare mocks
	awsConnectorMock := smock.MockAWSCloudConnectorService{}
	dmsMock := smock.MockDMSManagerService{}
	awsConnectorMock.On("GetDMSService").Return(&dmsMock)
	awsConnectorMock.On("GetConnectorID").Return("aws-12345")
	dmsMock.On("GetDMSByID", mock.Anything, mock.Anything).Return(&dms, nil)

	// Test logic
	handler := NewAWSIoTEventHandler(entry, &awsConnectorMock)
	handler.HandleMessage(message)

	// Assert
	awsConnectorMock.AssertExpectations(t)
	awsConnectorMock.AssertNotCalled(t, "UpdateDeviceShadow", mock.Anything, mock.Anything)
}

func loadDMSFromFile(t *testing.T, file string) models.DMS {
	content, err := os.ReadFile(file)
	if err != nil {
		t.Error(err)
	}

	var dms models.DMS
	json.Unmarshal(content, &dms)
	return dms
}
