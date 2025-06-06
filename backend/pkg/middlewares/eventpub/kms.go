package eventpub

import (
	"context"

	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type KMSEventPublisher struct {
	Next       services.KMSService
	eventMWPub ICloudEventMiddlewarePublisher
}

func NewKMSEventBusPublisher(eventMWPub ICloudEventMiddlewarePublisher) lservices.KMSMiddleware {
	return func(next services.KMSService) services.KMSService {
		return &KMSEventPublisher{
			Next:       next,
			eventMWPub: eventMWPub,
		}
	}
}

func (mw KMSEventPublisher) GetKeys(ctx context.Context) ([]*models.KeyInfo, error) {
	return mw.Next.GetKeys(ctx)
}

func (mw KMSEventPublisher) GetKeyByID(ctx context.Context, input services.GetByIDInput) (*models.KeyInfo, error) {
	return mw.Next.GetKeyByID(ctx, input)
}

func (mw KMSEventPublisher) CreateKey(ctx context.Context, input services.CreateKeyInput) (*models.KeyInfo, error) {
	return mw.Next.CreateKey(ctx, input)
}

func (mw KMSEventPublisher) DeleteKeyByID(ctx context.Context, input services.GetByIDInput) error {
	return mw.Next.DeleteKeyByID(ctx, input)
}

func (mw KMSEventPublisher) SignMessage(ctx context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	return mw.Next.SignMessage(ctx, input)
}

func (mw KMSEventPublisher) VerifySignature(ctx context.Context, input services.VerifySignInput) (bool, error) {
	return mw.Next.VerifySignature(ctx, input)
}

func (mw KMSEventPublisher) ImportKey(ctx context.Context, input services.ImportKeyInput) (*models.KeyInfo, error) {
	return mw.Next.ImportKey(ctx, input)
}
