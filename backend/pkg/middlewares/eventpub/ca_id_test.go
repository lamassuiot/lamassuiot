package eventpub

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type caIDService struct {
	services.CAService
	err error
}

func (s caIDService) CreateCA(context.Context, services.CreateCAInput) (*models.CACertificate, error) {
	return &models.CACertificate{ID: "generated-id"}, s.err
}
func (s caIDService) ImportCA(context.Context, services.ImportCAInput) (*models.CACertificate, error) {
	return &models.CACertificate{ID: "generated-id"}, s.err
}

func TestCACreationEventsUseGeneratedID(t *testing.T) {
	for _, importing := range []bool{false, true} {
		t.Run(map[bool]string{false: "/create", true: "/import"}[importing], func(t *testing.T) {
			publisher := new(CloudEventPublisherMock)
			eventType := models.EventCreateCAKey
			if importing {
				eventType = models.EventImportCAKey
			}
			publisher.On("PublishCloudEvent", mock.MatchedBy(func(ctx context.Context) bool {
				return ctx.Value(core.LamassuContextKeyEventSubject) == "ca/generated-id" && ctx.Value(core.LamassuContextKeyEventType) == eventType
			}), mock.MatchedBy(func(ca *models.CACertificate) bool { return ca.ID == "generated-id" })).Return()
			svc := NewCAEventBusPublisher(publisher)(caIDService{})
			var err error
			if importing {
				_, err = svc.ImportCA(context.Background(), services.ImportCAInput{})
			} else {
				_, err = svc.CreateCA(context.Background(), services.CreateCAInput{})
			}
			require.NoError(t, err)
			publisher.AssertExpectations(t)
		})
	}
}
