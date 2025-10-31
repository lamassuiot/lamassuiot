package eventpub

import (
	"context"
	"fmt"

	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type KMSEventPublisher struct {
	Next       services.KMSService
	eventMWPub ICloudEventPublisher
}

func NewKMSEventBusPublisher(eventMWPub ICloudEventPublisher) lservices.KMSMiddleware {
	return func(next services.KMSService) services.KMSService {
		return &KMSEventPublisher{
			Next:       next,
			eventMWPub: NewEventPublisherWithSourceMiddleware(eventMWPub, models.KMSSource),
		}
	}
}

func (mw KMSEventPublisher) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	return mw.Next.GetCryptoEngineProvider(ctx)
}

func (mw KMSEventPublisher) GetKeys(ctx context.Context, input services.GetKeysInput) (string, error) {
	return mw.Next.GetKeys(ctx, input)
}

func (mw KMSEventPublisher) GetKey(ctx context.Context, input services.GetKeyInput) (*models.Key, error) {
	return mw.Next.GetKey(ctx, input)
}

func (mw KMSEventPublisher) CreateKey(ctx context.Context, input services.CreateKeyInput) (output *models.Key, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventCreateKMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, "kms/unknown")

	defer func() {
		if err == nil {
			ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", output.KeyID))
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()

	return mw.Next.CreateKey(ctx, input)
}

func (mw KMSEventPublisher) ImportKey(ctx context.Context, input services.ImportKeyInput) (output *models.Key, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventImportKMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, "kms/unknown")

	defer func() {
		if err == nil {
			ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", output.KeyID))
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.ImportKey(ctx, input)
}

func (mw KMSEventPublisher) UpdateKeyMetadata(ctx context.Context, input services.UpdateKeyMetadataInput) (output *models.Key, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateKMSKeyMetadata)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", input.ID))

	prev, err := mw.GetKey(ctx, services.GetKeyInput{
		Identifier: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Key %s: %w", input.ID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.Key]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.Next.UpdateKeyMetadata(ctx, input)
}

func (mw KMSEventPublisher) UpdateKeyAliases(ctx context.Context, input services.UpdateKeyAliasesInput) (output *models.Key, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateKMSKeyAliases)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", input.ID))

	prev, err := mw.GetKey(ctx, services.GetKeyInput{
		Identifier: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Key %s: %w", input.ID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.Key]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.Next.UpdateKeyAliases(ctx, input)
}

func (mw KMSEventPublisher) UpdateKeyName(ctx context.Context, input services.UpdateKeyNameInput) (output *models.Key, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateKMSKeyName)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", input.ID))

	prev, err := mw.GetKey(ctx, services.GetKeyInput{
		Identifier: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Key %s: %w", input.ID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.Key]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.Next.UpdateKeyName(ctx, input)
}

func (mw KMSEventPublisher) DeleteKeyByID(ctx context.Context, input services.GetKeyInput) (err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventDeleteKMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", input.Identifier))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, input)
		}
	}()
	return mw.Next.DeleteKeyByID(ctx, input)
}

func (mw KMSEventPublisher) SignMessage(ctx context.Context, input services.SignMessageInput) (output *models.MessageSignature, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventSignMessageKMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", input.Identifier))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.SignMessage(ctx, input)
}

func (mw KMSEventPublisher) VerifySignature(ctx context.Context, input services.VerifySignInput) (output *models.MessageValidation, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventVerifySignatureKMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", input.Identifier))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.VerifySignature(ctx, input)
}
