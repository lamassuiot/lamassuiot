package auditpub

import (
	"context"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type KMSAuditEventPublisher struct {
	next     services.KMSService
	auditPub AuditPublisher
}

func NewKMSAuditEventBusPublisher(audit AuditPublisher) lservices.KMSMiddleware {
	return func(next services.KMSService) services.KMSService {
		return &KMSAuditEventPublisher{
			next: next,
			auditPub: AuditPublisher{
				ICloudEventPublisher: eventpub.NewEventPublisherWithSourceMiddleware(audit, models.KMSSource),
			},
		}
	}
}

func (mw KMSAuditEventPublisher) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	return mw.next.GetCryptoEngineProvider(ctx)
}

func (mw KMSAuditEventPublisher) GetKeys(ctx context.Context, input services.GetKeysInput) (string, error) {
	return mw.next.GetKeys(ctx, input)
}

func (mw KMSAuditEventPublisher) GetKey(ctx context.Context, input services.GetKeyInput) (*models.Key, error) {
	return mw.next.GetKey(ctx, input)
}

func (mw KMSAuditEventPublisher) GetKeyStats(ctx context.Context, input services.GetKeyStatsInput) (*models.KeyStats, error) {
	return mw.next.GetKeyStats(ctx, input)
}

func (mw KMSAuditEventPublisher) CreateKey(ctx context.Context, input services.CreateKeyInput) (output *models.Key, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateKMSKey, input, err, output)
	}()

	return mw.next.CreateKey(ctx, input)
}

func (mw KMSAuditEventPublisher) ImportKey(ctx context.Context, input services.ImportKeyInput) (output *models.Key, err error) {
	defer func() {
		input.PrivateKey = nil // Remove private key from audit logs
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventImportKMSKey, input, err, output)
	}()

	return mw.next.ImportKey(ctx, input)
}

func (mw KMSAuditEventPublisher) UpdateKeyMetadata(ctx context.Context, input services.UpdateKeyMetadataInput) (output *models.Key, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateKMSKeyMetadata, input, err, output)
	}()

	return mw.next.UpdateKeyMetadata(ctx, input)
}

func (mw KMSAuditEventPublisher) UpdateKeyAliases(ctx context.Context, input services.UpdateKeyAliasesInput) (output *models.Key, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateKMSKeyAliases, input, err, output)
	}()

	return mw.next.UpdateKeyAliases(ctx, input)
}

func (mw KMSAuditEventPublisher) UpdateKeyName(ctx context.Context, input services.UpdateKeyNameInput) (output *models.Key, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateKMSKeyName, input, err, output)
	}()

	return mw.next.UpdateKeyName(ctx, input)
}

func (mw KMSAuditEventPublisher) UpdateKeyTags(ctx context.Context, input services.UpdateKeyTagsInput) (output *models.Key, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateKMSKeyTags, input, err, output)
	}()

	return mw.next.UpdateKeyTags(ctx, input)
}

func (mw KMSAuditEventPublisher) DeleteKeyByID(ctx context.Context, input services.GetKeyInput) (err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventDeleteKMSKey, input, err, nil)
	}()

	return mw.next.DeleteKeyByID(ctx, input)
}

func (mw KMSAuditEventPublisher) SignMessage(ctx context.Context, input services.SignMessageInput) (output *models.MessageSignature, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventSignMessageKMSKey, input, err, output)
	}()

	return mw.next.SignMessage(ctx, input)
}

func (mw KMSAuditEventPublisher) VerifySignature(ctx context.Context, input services.VerifySignInput) (output *models.MessageValidation, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventVerifySignatureKMSKey, input, err, output)
	}()

	return mw.next.VerifySignature(ctx, input)
}
