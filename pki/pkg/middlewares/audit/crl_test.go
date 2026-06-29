package auditpub

import (
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
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
			name: "UpdateVARole with errors - Audit event produced",
			test: func(t *testing.T) {
				crlAuditWithErrors(t, "UpdateVARole", services.UpdateVARoleInput{}, models.EventUpdateVARole, &models.VARole{})
			},
		},
		{
			name: "UpdateVARole without errors - Audit event produced",
			test: func(t *testing.T) {
				crlAuditWithoutErrors(t, "UpdateVARole", services.UpdateVARoleInput{}, models.EventUpdateVARole, &models.VARole{})
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
			name: "InitCRLRole with errors - Audit event produced",
			test: func(t *testing.T) {
				crlAuditWithErrors(t, "InitCRLRole", "", models.EventInitCRLRole, &models.VARole{})
			},
		},
		{
			name: "InitCRLRole without errors - Audit event produced",
			test: func(t *testing.T) {
				crlAuditWithoutErrors(t, "InitCRLRole", "", models.EventInitCRLRole, &models.VARole{})
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, tc.test)
	}
}
