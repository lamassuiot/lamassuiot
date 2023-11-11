package amqppub

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
)

type amqpCAEventPublisher struct {
	next           services.CAService
	eventPublisher *messaging.AMQPSetup
}

func NewCAAmqpEventPublisher(amqpPublisher *messaging.AMQPSetup) services.CAMiddleware {
	return func(next services.CAService) services.CAService {
		return &amqpCAEventPublisher{
			next:           next,
			eventPublisher: amqpPublisher,
		}
	}
}

func (mw amqpCAEventPublisher) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	return mw.next.GetCryptoEngineProvider(ctx)
}

func (mw amqpCAEventPublisher) GetStats(ctx context.Context) (*models.CAStats, error) {
	return mw.next.GetStats(ctx)
}

func (mw amqpCAEventPublisher) CreateCA(ctx context.Context, input services.CreateCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventCreateCAKey, output)
		}
	}()
	return mw.next.CreateCA(ctx, input)
}

func (mw amqpCAEventPublisher) ImportCA(ctx context.Context, input services.ImportCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventImportCAKey, output)
		}
	}()
	return mw.next.ImportCA(ctx, input)
}

func (mw amqpCAEventPublisher) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	return mw.next.GetCAByID(ctx, input)
}

func (mw amqpCAEventPublisher) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	return mw.next.GetCAs(ctx, input)
}

func (mw amqpCAEventPublisher) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	return mw.next.GetCAsByCommonName(ctx, input)
}

func (mw amqpCAEventPublisher) GetCABySerialNumber(ctx context.Context, input services.GetCABySerialNumberInput) (*models.CACertificate, error) {
	return mw.next.GetCABySerialNumber(ctx, input)
}

func (mw amqpCAEventPublisher) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (output *models.CACertificate, err error) {
	prev, err := mw.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: input.CAID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get CA %s: %w", input.CAID, err)
	}

	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventUpdateCAStatusKey, models.UpdateModel[models.CACertificate]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateCAStatus(ctx, input)
}
func (mw amqpCAEventPublisher) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (output *models.CACertificate, err error) {
	prev, err := mw.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: input.CAID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get CA %s: %w", input.CAID, err)
	}

	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventUpdateCAMetadataKey, models.UpdateModel[models.CACertificate]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateCAMetadata(ctx, input)
}

func (mw amqpCAEventPublisher) DeleteCA(ctx context.Context, input services.DeleteCAInput) (err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventDeleteCAKey, input)
		}
	}()
	return mw.next.DeleteCA(ctx, input)
}

func (mw amqpCAEventPublisher) SignCertificate(ctx context.Context, input services.SignCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventSignCertificateKey, output)
		}
	}()
	return mw.next.SignCertificate(ctx, input)
}

func (mw amqpCAEventPublisher) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventCreateCertificateKey, output)
		}
	}()
	return mw.next.CreateCertificate(ctx, input)
}

func (mw amqpCAEventPublisher) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, "ca.certificate.import", output)
		}
	}()
	return mw.next.ImportCertificate(ctx, input)
}

func (mw amqpCAEventPublisher) SignatureSign(ctx context.Context, input services.SignatureSignInput) (output []byte, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventSignatureSignKey, output)
		}
	}()
	return mw.next.SignatureSign(ctx, input)
}

func (mw amqpCAEventPublisher) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (output bool, err error) {
	return mw.next.SignatureVerify(ctx, input)
}

func (mw amqpCAEventPublisher) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	return mw.next.GetCertificateBySerialNumber(ctx, input)
}

func (mw amqpCAEventPublisher) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	return mw.next.GetCertificates(ctx, input)
}

func (mw amqpCAEventPublisher) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	return mw.next.GetCertificatesByCA(ctx, input)
}

func (mw amqpCAEventPublisher) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	return mw.next.GetCertificatesByExpirationDate(ctx, input)
}

func (mw amqpCAEventPublisher) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (output *models.Certificate, err error) {
	prev, err := mw.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Certificate %s: %w", input.SerialNumber, err)
	}

	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventUpdateCertificateStatusKey, models.UpdateModel[models.Certificate]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.next.UpdateCertificateStatus(ctx, input)
}

func (mw amqpCAEventPublisher) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	return mw.next.GetCertificatesByCaAndStatus(ctx, input)
}

func (mw amqpCAEventPublisher) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	return mw.next.GetCertificatesByStatus(ctx, input)
}

func (mw amqpCAEventPublisher) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (output *models.Certificate, err error) {
	prev, err := mw.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Certificate %s: %w", input.SerialNumber, err)
	}

	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventUpdateCertificateMetadataKey, models.UpdateModel[models.Certificate]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.next.UpdateCertificateMetadata(ctx, input)
}
