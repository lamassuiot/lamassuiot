package eventpub

import (
	"context"

	"github.com/lamassuiot/lamassuiot/service/kms"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/eventpublisher"
)

type KMSAuditEventPublisher struct {
	next     kms.KMSService
	auditPub eventpublisher.AuditPublisher
}

func NewKMSAuditEventBusPublisher(audit eventpublisher.AuditPublisher) kms.KMSMiddleware {
	return func(next kms.KMSService) kms.KMSService {
		return &KMSAuditEventPublisher{
			next: next,
			auditPub: eventpublisher.AuditPublisher{
				ICloudEventPublisher: eventpublisher.NewEventPublisherWithSourceMiddleware(audit, kms.SERVICE_SOURCE),
			},
		}
	}
}

func (mw KMSAuditEventPublisher) GetKeys(ctx context.Context, input kms.GetKeysInput) (string, error) {
	return mw.next.GetKeys(ctx, input)
}

func (mw KMSAuditEventPublisher) GetKeyByID(ctx context.Context, input kms.GetKeyByIDInput) (*kms.Key, error) {
	return mw.next.GetKeyByID(ctx, input)
}

func (mw KMSAuditEventPublisher) CreateKey(ctx context.Context, input kms.CreateKeyInput) (output *kms.Key, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, kms.EventCreateKMSKey, input, err, output)
	}()

	return mw.next.CreateKey(ctx, input)
}

func (mw KMSAuditEventPublisher) DeleteKeyByID(ctx context.Context, input kms.GetKeyByIDInput) (err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, kms.EventDeleteKMSKey, input, err, nil)
	}()

	return mw.next.DeleteKeyByID(ctx, input)
}

func (mw KMSAuditEventPublisher) SignMessage(ctx context.Context, input kms.SignMessageInput) (output *kms.MessageSignature, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, kms.EventSignMessageKMSKey, input, err, output)
	}()

	return mw.next.SignMessage(ctx, input)
}

func (mw KMSAuditEventPublisher) VerifySignature(ctx context.Context, input kms.VerifySignInput) (output *kms.MessageValidation, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, kms.EventVerifySignatureKMSKey, input, err, output)
	}()

	return mw.next.VerifySignature(ctx, input)
}

func (mw KMSAuditEventPublisher) ImportKey(ctx context.Context, input kms.ImportKeyInput) (output *kms.Key, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, kms.EventImportKMSKey, input, err, output)
	}()

	return mw.next.ImportKey(ctx, input)
}
