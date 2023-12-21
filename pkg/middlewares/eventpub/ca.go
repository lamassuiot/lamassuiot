package eventpub

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/messaging"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

type caEventPublisher struct {
	next     services.CAService
	eventBus *messaging.MessagingEngine
}

func NewCAEventBusPublisher(engine *messaging.MessagingEngine) services.CAMiddleware {
	return func(next services.CAService) services.CAService {
		return &caEventPublisher{
			next:     next,
			eventBus: engine,
		}
	}
}

func (mw caEventPublisher) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	return mw.next.GetCryptoEngineProvider(ctx)
}

func (mw caEventPublisher) GetStats(ctx context.Context) (*models.CAStats, error) {
	return mw.next.GetStats(ctx)
}
func (mw caEventPublisher) GetStatsByCAID(ctx context.Context, input services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	return mw.next.GetStatsByCAID(ctx, input)
}

func (mw caEventPublisher) CreateCA(ctx context.Context, input services.CreateCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventBus.PublishCloudEvent(ctx, models.EventCreateCAKey, output)
		}
	}()
	return mw.next.CreateCA(ctx, input)
}

func (mw caEventPublisher) ImportCA(ctx context.Context, input services.ImportCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventBus.PublishCloudEvent(ctx, models.EventImportCAKey, output)
		}
	}()
	return mw.next.ImportCA(ctx, input)
}

func (mw caEventPublisher) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	return mw.next.GetCAByID(ctx, input)
}

func (mw caEventPublisher) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	return mw.next.GetCAs(ctx, input)
}

func (mw caEventPublisher) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	return mw.next.GetCAsByCommonName(ctx, input)
}

func (mw caEventPublisher) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (output *models.CACertificate, err error) {
	prev, err := mw.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: input.CAID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get CA %s: %w", input.CAID, err)
	}

	defer func() {
		if err == nil {
			mw.eventBus.PublishCloudEvent(ctx, models.EventUpdateCAStatusKey, models.UpdateModel[models.CACertificate]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateCAStatus(ctx, input)
}
func (mw caEventPublisher) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (output *models.CACertificate, err error) {
	prev, err := mw.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: input.CAID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get CA %s: %w", input.CAID, err)
	}

	defer func() {
		if err == nil {
			mw.eventBus.PublishCloudEvent(ctx, models.EventUpdateCAMetadataKey, models.UpdateModel[models.CACertificate]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateCAMetadata(ctx, input)
}

func (mw caEventPublisher) DeleteCA(ctx context.Context, input services.DeleteCAInput) (err error) {
	defer func() {
		if err == nil {
			mw.eventBus.PublishCloudEvent(ctx, models.EventDeleteCAKey, input)
		}
	}()
	return mw.next.DeleteCA(ctx, input)
}

func (mw caEventPublisher) SignCertificate(ctx context.Context, input services.SignCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventBus.PublishCloudEvent(ctx, models.EventSignCertificateKey, output)
		}
	}()
	return mw.next.SignCertificate(ctx, input)
}

func (mw caEventPublisher) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventBus.PublishCloudEvent(ctx, models.EventCreateCertificateKey, output)
		}
	}()
	return mw.next.CreateCertificate(ctx, input)
}

func (mw caEventPublisher) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventBus.PublishCloudEvent(ctx, "ca.certificate.import", output)
		}
	}()
	return mw.next.ImportCertificate(ctx, input)
}

func (mw caEventPublisher) SignatureSign(ctx context.Context, input services.SignatureSignInput) (output []byte, err error) {
	defer func() {
		if err == nil {
			mw.eventBus.PublishCloudEvent(ctx, models.EventSignatureSignKey, output)
		}
	}()
	return mw.next.SignatureSign(ctx, input)
}

func (mw caEventPublisher) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (output bool, err error) {
	return mw.next.SignatureVerify(ctx, input)
}

func (mw caEventPublisher) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	return mw.next.GetCertificateBySerialNumber(ctx, input)
}

func (mw caEventPublisher) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	return mw.next.GetCertificates(ctx, input)
}

func (mw caEventPublisher) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	return mw.next.GetCertificatesByCA(ctx, input)
}

func (mw caEventPublisher) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	return mw.next.GetCertificatesByExpirationDate(ctx, input)
}

func (mw caEventPublisher) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (output *models.Certificate, err error) {
	prev, err := mw.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Certificate %s: %w", input.SerialNumber, err)
	}

	defer func() {
		if err == nil {
			mw.eventBus.PublishCloudEvent(ctx, models.EventUpdateCertificateStatusKey, models.UpdateModel[models.Certificate]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.next.UpdateCertificateStatus(ctx, input)
}

func (mw caEventPublisher) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	return mw.next.GetCertificatesByCaAndStatus(ctx, input)
}

func (mw caEventPublisher) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	return mw.next.GetCertificatesByStatus(ctx, input)
}

func (mw caEventPublisher) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (output *models.Certificate, err error) {
	prev, err := mw.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Certificate %s: %w", input.SerialNumber, err)
	}

	defer func() {
		if err == nil {
			mw.eventBus.PublishCloudEvent(ctx, models.EventUpdateCertificateMetadataKey, models.UpdateModel[models.Certificate]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.next.UpdateCertificateMetadata(ctx, input)
}
