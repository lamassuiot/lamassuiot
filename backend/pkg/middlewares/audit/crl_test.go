package auditpub

import (
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func crlAuditEventChecker(event models.EventType, expectations []func(*svcmock.MockVAService), operation func(services.CRLService), assertions func(*CloudEventPublisherMock, *svcmock.MockVAService)) {
	mockCRLService := new(svcmock.MockVAService)
	mockCloudEventPub := new(CloudEventPublisherMock)
	auditPublisher := AuditPublisher{
		ICloudEventPublisher: mockCloudEventPub,
	}
	crlAuditPublisherMw := NewCRLAuditEventPublisher(auditPublisher)
	crlAuditPublisher := crlAuditPublisherMw(mockCRLService)

	for _, expectation := range expectations {
		expectation(mockCRLService)
	}

	mockCloudEventPub.On("PublishCloudEvent", mock.Anything, mock.Anything)
	operation(crlAuditPublisher)

	assertions(mockCloudEventPub, mockCRLService)
}

func crlAuditWithoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockVAService)) {
	expectations := []func(*svcmock.MockVAService){
		func(mockCRLService *svcmock.MockVAService) {
			mockCRLService.On(method, mock.Anything, mock.Anything).Return(expectedOutput, nil)
		},
	}
	expectations = append(expectations, extra...)

	operation := func(crlMiddleware services.CRLService) {
		m := reflect.ValueOf(crlMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.Nil(t, r[1].Interface())
	}

	assertions := func(mockCloudEventPub *CloudEventPublisherMock, mockCRLService *svcmock.MockVAService) {
		mockCRLService.AssertExpectations(t)
		mockCloudEventPub.AssertExpectations(t)
	}

	crlAuditEventChecker(event, expectations, operation, assertions)
}

func crlAuditWithErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockVAService)) {
	expectations := []func(*svcmock.MockVAService){
		func(mockCRLService *svcmock.MockVAService) {
			mockCRLService.On(method, mock.Anything, mock.Anything).Return(expectedOutput, errors.New("some error"))
		},
	}
	expectations = append(expectations, extra...)

	operation := func(crlMiddleware services.CRLService) {
		m := reflect.ValueOf(crlMiddleware).MethodByName(method)
		r := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(input)})
		assert.NotNil(t, r[1].Interface())
	}

	assertions := func(mockCloudEventPub *CloudEventPublisherMock, mockCRLService *svcmock.MockVAService) {
		mockCRLService.AssertExpectations(t)
		mockCloudEventPub.AssertExpectations(t)
	}

	crlAuditEventChecker(event, expectations, operation, assertions)
}

func TestCRLAuditEventPublisher(t *testing.T) {
	var testcases = []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "UpdateCRLSettings with errors - Audit event produced",
			test: func(t *testing.T) {
				crlAuditWithErrors(t, "UpdateCRLSettings", services.UpdateCRLSettingsInput{}, models.EventUpdateCRLSettings, &models.CRLSettings{})
			},
		},
		{
			name: "UpdateCRLSettings without errors - Audit event produced",
			test: func(t *testing.T) {
				crlAuditWithoutErrors(t, "UpdateCRLSettings", services.UpdateCRLSettingsInput{}, models.EventUpdateCRLSettings, &models.CRLSettings{})
			},
		},
		{
			name: "CalculateCRL with errors - Audit event produced",
			test: func(t *testing.T) {
				crlAuditWithErrors(t, "CalculateCRL", services.CalculateCRLInput{}, models.EventCreateCRL, &x509.RevocationList{})
			},
		},
		{
			name: "CalculateCRL without errors - Audit event produced",
			test: func(t *testing.T) {
				crlAuditWithoutErrors(t, "CalculateCRL", services.CalculateCRLInput{}, models.EventCreateCRL, &x509.RevocationList{})
			},
		},
		{
			name: "InitCRLSettings with errors - Audit event produced",
			test: func(t *testing.T) {
				crlAuditWithErrors(t, "InitCRLSettings", "", models.EventInitCRLSettings, &models.CRLSettings{})
			},
		},
		{
			name: "InitCRLSettings without errors - Audit event produced",
			test: func(t *testing.T) {
				crlAuditWithoutErrors(t, "InitCRLSettings", "", models.EventInitCRLSettings, &models.CRLSettings{})
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, tc.test)
	}
}
