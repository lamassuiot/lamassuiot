package auditpub

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func dmsAuditEventChecker(event models.EventType, expectations []func(*svcmock.MockDMSManagerService), operation func(services.DMSManagerService), assertions func(*CloudEventPublisherMock, *svcmock.MockDMSManagerService)) {
	mockDMSService := new(svcmock.MockDMSManagerService)
	mockCloudEventPub := new(CloudEventPublisherMock)
	auditPublisher := AuditPublisher{
		ICloudEventPublisher: mockCloudEventPub,
	}
	dmsAuditPublisherMw := NewDmsAuditEventPublisher(auditPublisher)
	dmsAuditPublisher := dmsAuditPublisherMw(mockDMSService)

	for _, expectation := range expectations {
		expectation(mockDMSService)
	}

	mockCloudEventPub.On("PublishCloudEvent", mock.Anything, mock.Anything)
	operation(dmsAuditPublisher)

	assertions(mockCloudEventPub, mockDMSService)
}

func dmsAuditWithoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDMSManagerService)) {
	expectations := []func(*svcmock.MockDMSManagerService){
		func(mockDMSService *svcmock.MockDMSManagerService) {
			mockDMSService.On(method, mock.Anything, mock.Anything).Return(expectedOutput, nil)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(dmsMiddleware services.DMSManagerService) {
		m := reflect.ValueOf(dmsMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.Nil(t, r[1].Interface())
	}

	assertions := func(mockCloudEventPub *CloudEventPublisherMock, mockDMSService *svcmock.MockDMSManagerService) {
		mockDMSService.AssertExpectations(t)
		mockCloudEventPub.AssertExpectations(t)
	}

	dmsAuditEventChecker(event, expectations, operation, assertions)
}

func dmsAuditWithErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockDMSManagerService)) {
	expectations := []func(*svcmock.MockDMSManagerService){
		func(mockDMSService *svcmock.MockDMSManagerService) {
			mockDMSService.On(method, mock.Anything, mock.Anything).Return(expectedOutput, errors.New("some error"))
		},
	}
	expectations = append(expectations, extra...)

	operation := func(dmsMiddleware services.DMSManagerService) {
		m := reflect.ValueOf(dmsMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.NotNil(t, r[1].Interface())
	}

	assertions := func(mockCloudEventPub *CloudEventPublisherMock, mockDMSService *svcmock.MockDMSManagerService) {
		mockDMSService.AssertExpectations(t)
		mockCloudEventPub.AssertExpectations(t)
	}

	dmsAuditEventChecker(event, expectations, operation, assertions)
}

func TestDMSAuditEventPublisher(t *testing.T) {
	var testcases = []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "CreateDMS with errors - Audit event produced",
			test: func(t *testing.T) {
				dmsAuditWithErrors(t, "CreateDMS", services.CreateDMSInput{}, models.EventCreateDMSKey, &models.DMS{})
			},
		},
		{
			name: "CreateDMS without errors - Audit event produced",
			test: func(t *testing.T) {
				dmsAuditWithoutErrors(t, "CreateDMS", services.CreateDMSInput{}, models.EventCreateDMSKey, &models.DMS{})
			},
		},
		{
			name: "UpdateDMS with errors - Audit event produced",
			test: func(t *testing.T) {
				dmsAuditWithErrors(t, "UpdateDMS", services.UpdateDMSInput{}, models.EventUpdateDMSKey, &models.DMS{})
			},
		},
		{
			name: "UpdateDMS without errors - Audit event produced",
			test: func(t *testing.T) {
				dmsAuditWithoutErrors(t, "UpdateDMS", services.UpdateDMSInput{}, models.EventUpdateDMSKey, &models.DMS{})
			},
		},
		{
			name: "BindIdentityToDevice with errors - Audit event produced",
			test: func(t *testing.T) {
				dmsAuditWithErrors(t, "BindIdentityToDevice", services.BindIdentityToDeviceInput{}, models.EventBindDeviceIdentityKey, &models.BindIdentityToDeviceOutput{})
			},
		},
		{
			name: "BindIdentityToDevice without errors - Audit event produced",
			test: func(t *testing.T) {
				dmsAuditWithoutErrors(t, "BindIdentityToDevice", services.BindIdentityToDeviceInput{}, models.EventBindDeviceIdentityKey, &models.BindIdentityToDeviceOutput{})
			},
		},
		{
			name: "UpdateDMSMetadata with errors - Audit event produced",
			test: func(t *testing.T) {
				dmsAuditWithErrors(t, "UpdateDMSMetadata", services.UpdateDMSMetadataInput{}, models.EventUpdateDMSMetadataKey, &models.DMS{})
			},
		},
		{
			name: "UpdateDMSMetadata without errors - Audit event produced",
			test: func(t *testing.T) {
				dmsAuditWithoutErrors(t, "UpdateDMSMetadata", services.UpdateDMSMetadataInput{}, models.EventUpdateDMSMetadataKey, &models.DMS{})
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, tc.test)
	}
}
