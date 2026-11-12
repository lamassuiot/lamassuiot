package eventpub

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/stretchr/testify/mock"
)

// The subject of the CRL events is the ID of the CA, not its SKI: CAs sharing a key share the SKI.
func TestCRLEventPublisherSubjectsUseCAID(t *testing.T) {
	for _, tc := range []struct {
		name      string
		eventType models.EventType
		call      func(svc services.CRLService)
		setup     func(svc *svcmock.MockVAService)
	}{
		{
			name: "init", eventType: models.EventInitCRLSettings,
			setup: func(svc *svcmock.MockVAService) {
				svc.On("InitCRLSettings", mock.Anything, "ca-1").Return(&models.CRLSettings{}, nil)
			},
			call: func(svc services.CRLService) { _, _ = svc.InitCRLSettings(context.Background(), "ca-1") },
		},
		{
			name: "update", eventType: models.EventUpdateCRLSettings,
			setup: func(svc *svcmock.MockVAService) {
				svc.On("UpdateCRLSettings", mock.Anything, mock.Anything).Return(&models.CRLSettings{}, nil)
			},
			call: func(svc services.CRLService) {
				_, _ = svc.UpdateCRLSettings(context.Background(), services.UpdateCRLSettingsInput{CAID: "ca-1"})
			},
		},
		{
			name: "calculate", eventType: models.EventCreateCRL,
			setup: func(svc *svcmock.MockVAService) {
				svc.On("CalculateCRL", mock.Anything, mock.Anything).Return(&x509.RevocationList{}, nil)
			},
			call: func(svc services.CRLService) {
				_, _ = svc.CalculateCRL(context.Background(), services.CalculateCRLInput{CAID: "ca-1"})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := new(svcmock.MockVAService)
			tc.setup(next)
			pub := new(CloudEventPublisherMock)
			pub.On("PublishCloudEvent", mock.MatchedBy(func(ctx context.Context) bool {
				return ctx.Value(core.LamassuContextKeyEventSubject) == "crl/ca-1" && ctx.Value(core.LamassuContextKeyEventType) == tc.eventType
			}), mock.Anything).Return()

			tc.call(NewCRLEventPublisher(pub)(next))

			pub.AssertExpectations(t)
		})
	}
}
