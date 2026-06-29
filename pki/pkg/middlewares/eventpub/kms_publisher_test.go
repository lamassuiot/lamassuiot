package eventpub

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
)

// KMS test configuration
var kmsTestConfig = EventTestConfig[services.KMSService, *svcmock.MockKMSService]{
	NewPublisher: func(pub *CloudEventPublisherMock) func(services.KMSService) services.KMSService {
		return NewKMSEventBusPublisher(pub)
	},
	CreateMockService: func() *svcmock.MockKMSService {
		return new(svcmock.MockKMSService)
	},
}

// Convenience wrappers for KMS testing
func kmsWithoutErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockKMSService)) {
	WithoutErrors(t, kmsTestConfig, method, input, event, expectedOutput, extra...)
}

func kmsWithErrors[E any, O any](t *testing.T, method string, input E, event models.EventType, expectedOutput O, extra ...func(*svcmock.MockKMSService)) {
	WithErrors(t, kmsTestConfig, method, input, event, expectedOutput, extra...)
}

func kmsWithoutErrorsSingleResult[E any](t *testing.T, method string, input E, event models.EventType, extra ...func(*svcmock.MockKMSService)) {
	WithoutErrorsSingleResult(t, kmsTestConfig, method, input, event, extra...)
}

func kmsWithErrorsSingleResult[E any](t *testing.T, method string, input E, event models.EventType, extra ...func(*svcmock.MockKMSService)) {
	WithErrorsSingleResult(t, kmsTestConfig, method, input, event, extra...)
}

func TestKMSEventPublisher(t *testing.T) {
	var testcases = []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "CreateKey with errors - Not fire event",
			test: func(t *testing.T) {
				kmsWithErrors(t, "CreateKey", services.CreateKeyInput{}, models.EventCreateKMSKey, &models.Key{})
			},
		},
		{
			name: "CreateKey without errors - fire event",
			test: func(t *testing.T) {
				kmsWithoutErrors(t, "CreateKey", services.CreateKeyInput{}, models.EventCreateKMSKey, &models.Key{})
			},
		},
		{
			name: "DeleteKeyByID with errors - Not fire event",
			test: func(t *testing.T) {
				kmsWithErrorsSingleResult(t, "DeleteKeyByID", services.GetKeyInput{}, models.EventDeleteKMSKey)
			},
		},
		{
			name: "DeleteKeyByID without errors - fire event",
			test: func(t *testing.T) {
				kmsWithoutErrorsSingleResult(t, "DeleteKeyByID", services.GetKeyInput{}, models.EventDeleteKMSKey)
			},
		},
		{
			name: "SignMessage with errors - Not fire event",
			test: func(t *testing.T) {
				kmsWithErrors(t, "SignMessage", services.SignMessageInput{}, models.EventSignMessageKMSKey, &models.MessageSignature{})
			},
		},
		{
			name: "SignMessage without errors - fire event",
			test: func(t *testing.T) {
				kmsWithoutErrors(t, "SignMessage", services.SignMessageInput{}, models.EventSignMessageKMSKey, &models.MessageSignature{})
			},
		},
		{
			name: "VerifySignature with errors - Not fire event",
			test: func(t *testing.T) {
				kmsWithErrors(t, "VerifySignature", services.VerifySignInput{}, models.EventVerifySignatureKMSKey, &models.MessageValidation{})
			},
		},
		{
			name: "VerifySignature without errors - fire event",
			test: func(t *testing.T) {
				kmsWithoutErrors(t, "VerifySignature", services.VerifySignInput{}, models.EventVerifySignatureKMSKey, &models.MessageValidation{})
			},
		},
		{
			name: "ImportKey with errors - Not fire event",
			test: func(t *testing.T) {
				kmsWithErrors(t, "ImportKey", services.ImportKeyInput{}, models.EventImportKMSKey, &models.Key{})
			},
		},
		{
			name: "ImportKey without errors - fire event",
			test: func(t *testing.T) {
				kmsWithoutErrors(t, "ImportKey", services.ImportKeyInput{}, models.EventImportKMSKey, &models.Key{})
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, tc.test)
	}
}
