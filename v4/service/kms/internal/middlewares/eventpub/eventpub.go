package eventpub

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/eventpublisher"
	"github.com/lamassuiot/lamassuiot/service/kms"
)

type KMSEventPublisher struct {
	Next       kms.KMSService
	eventMWPub eventpublisher.ICloudEventPublisher
}

func NewKMSEventBusPublisher(eventMWPub eventpublisher.ICloudEventPublisher) kms.KMSMiddleware {
	return func(next kms.KMSService) kms.KMSService {
		return &KMSEventPublisher{
			Next:       next,
			eventMWPub: eventpublisher.NewEventPublisherWithSourceMiddleware(eventMWPub, kms.ServiceSource),
		}
	}
}

func (mw KMSEventPublisher) GetKeys(ctx context.Context, input kms.GetKeysInput) (string, error) {
	return mw.Next.GetKeys(ctx, input)
}

func (mw KMSEventPublisher) GetKeyByID(ctx context.Context, input kms.GetKeyByIDInput) (*kms.Key, error) {
	return mw.Next.GetKeyByID(ctx, input)
}

func (mw KMSEventPublisher) CreateKey(ctx context.Context, input kms.CreateKeyInput) (output *kms.Key, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, kms.EventCreateKMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, "kms/unknown")

	defer func() {
		if err == nil {
			ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", output.ID))
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()

	return mw.Next.CreateKey(ctx, input)
}

func (mw KMSEventPublisher) DeleteKeyByID(ctx context.Context, input kms.GetKeyByIDInput) (err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, kms.EventDeleteKMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", input.ID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, input)
		}
	}()
	return mw.Next.DeleteKeyByID(ctx, input)
}

func (mw KMSEventPublisher) SignMessage(ctx context.Context, input kms.SignMessageInput) (output *kms.MessageSignature, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, kms.EventSignMessageKMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", input.KeyID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.SignMessage(ctx, input)
}

func (mw KMSEventPublisher) VerifySignature(ctx context.Context, input kms.VerifySignInput) (output *kms.MessageValidation, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, kms.EventVerifySignatureKMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", input.KeyID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.VerifySignature(ctx, input)
}

func (mw KMSEventPublisher) ImportKey(ctx context.Context, input kms.ImportKeyInput) (output *kms.Key, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, kms.EventImportKMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, "kms/unknown")

	defer func() {
		if err == nil {
			ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("kms/%s", output.ID))
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.Next.ImportKey(ctx, input)
}
