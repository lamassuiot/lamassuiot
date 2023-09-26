package amqppub

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
)

type amqpEventPublisher struct {
	next           services.CAService
	eventPublisher *messaging.AMQPSetup
}

const caSource = "lamassuiot.ca"

func NewCAAmqpEventPublisher(amqpPublisher *messaging.AMQPSetup) services.CAMiddleware {
	return func(next services.CAService) services.CAService {
		return &amqpEventPublisher{
			next:           next,
			eventPublisher: amqpPublisher,
		}
	}
}

func (mw amqpEventPublisher) GetStats(ctx context.Context) (*models.CAStats, error) {
	return mw.next.GetStats(ctx)
}
func (mw amqpEventPublisher) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	return mw.next.GetCryptoEngineProvider(ctx)
}

func (mw amqpEventPublisher) CreateCA(ctx context.Context, input services.CreateCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.create", caSource, output)
		}
	}()
	return mw.next.CreateCA(ctx, input)
}

func (mw amqpEventPublisher) ImportCA(ctx context.Context, input services.ImportCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.import", caSource, output)
		}
	}()
	return mw.next.ImportCA(ctx, input)
}

func (mw amqpEventPublisher) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	return mw.next.GetCAByID(ctx, input)
}

func (mw amqpEventPublisher) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	return mw.next.GetCAs(ctx, input)
}

func (mw amqpEventPublisher) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	return mw.next.GetCAsByCommonName(ctx, input)
}

func (mw amqpEventPublisher) GetCABySerialNumber(ctx context.Context, input services.GetCABySerialNumberInput) (*models.CACertificate, error) {
	return mw.next.GetCABySerialNumber(ctx, input)
}

func (mw amqpEventPublisher) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.update.status", caSource, output)
		}
	}()
	return mw.next.UpdateCAStatus(ctx, input)
}
func (mw amqpEventPublisher) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.update.metadata", caSource, output)
		}
	}()
	return mw.next.UpdateCAMetadata(ctx, input)
}

func (mw amqpEventPublisher) DeleteCA(ctx context.Context, input services.DeleteCAInput) (err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.delete", caSource, input)
		}
	}()
	return mw.next.DeleteCA(ctx, input)
}

func (mw amqpEventPublisher) SignCertificate(ctx context.Context, input services.SignCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.certificate.sign", caSource, output)
		}
	}()
	return mw.next.SignCertificate(ctx, input)
}

func (mw amqpEventPublisher) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.certificate.create", caSource, output)
		}
	}()
	return mw.next.CreateCertificate(ctx, input)
}

func (mw amqpEventPublisher) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.certificate.import", caSource, output)
		}
	}()
	return mw.next.ImportCertificate(ctx, input)
}

func (mw amqpEventPublisher) SignatureSign(ctx context.Context, input services.SignatureSignInput) (output []byte, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.signature.sign", caSource, output)
		}
	}()
	return mw.next.SignatureSign(ctx, input)
}

func (mw amqpEventPublisher) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (output bool, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.signature.verify", caSource, output)
		}
	}()
	return mw.next.SignatureVerify(ctx, input)
}

func (mw amqpEventPublisher) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	return mw.next.GetCertificateBySerialNumber(ctx, input)
}

func (mw amqpEventPublisher) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	return mw.next.GetCertificates(ctx, input)
}

func (mw amqpEventPublisher) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	return mw.next.GetCertificatesByCA(ctx, input)
}

func (mw amqpEventPublisher) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	return mw.next.GetCertificatesByExpirationDate(ctx, input)
}

func (mw amqpEventPublisher) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("certificate.update.status", caSource, output)
		}
	}()
	return mw.next.UpdateCertificateStatus(ctx, input)
}

func (mw amqpEventPublisher) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	return mw.next.GetCertificatesByCaAndStatus(ctx, input)
}

func (mw amqpEventPublisher) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("certificate.update.metadata", caSource, output)
		}
	}()
	return mw.next.UpdateCertificateMetadata(ctx, input)
}
