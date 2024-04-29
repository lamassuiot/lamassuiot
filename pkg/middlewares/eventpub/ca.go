package eventpub

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

type CAEventPublisher struct {
	Next       services.CAService
	eventMWPub CloudEventMiddlewarePublisher
}

func NewCAEventBusPublisher(eventMWPub CloudEventMiddlewarePublisher) services.CAMiddleware {
	return func(next services.CAService) services.CAService {
		return &CAEventPublisher{
			Next:       next,
			eventMWPub: eventMWPub,
		}
	}
}

func (mw CAEventPublisher) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	return mw.Next.GetCryptoEngineProvider(ctx)
}

func (mw CAEventPublisher) GetStats(ctx context.Context) (*models.CAStats, error) {
	return mw.Next.GetStats(ctx)
}
func (mw CAEventPublisher) GetStatsByCAID(ctx context.Context, input services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	return mw.Next.GetStatsByCAID(ctx, input)
}

func (mw CAEventPublisher) CreateCA(ctx context.Context, input services.CreateCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventCreateCAKey, output)
		}
	}()
	return mw.Next.CreateCA(ctx, input)
}

func (mw CAEventPublisher) ImportCA(ctx context.Context, input services.ImportCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventImportCAKey, output)
		}
	}()
	return mw.Next.ImportCA(ctx, input)
}

func (mw CAEventPublisher) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	return mw.Next.GetCAByID(ctx, input)
}

func (mw CAEventPublisher) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	return mw.Next.GetCAs(ctx, input)
}

func (mw CAEventPublisher) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	return mw.Next.GetCAsByCommonName(ctx, input)
}

func (mw CAEventPublisher) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (output *models.CACertificate, err error) {
	prev, err := mw.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: input.CAID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get CA %s: %w", input.CAID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventUpdateCAStatusKey, models.UpdateModel[models.CACertificate]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.Next.UpdateCAStatus(ctx, input)
}
func (mw CAEventPublisher) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (output *models.CACertificate, err error) {
	prev, err := mw.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: input.CAID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get CA %s: %w", input.CAID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventUpdateCAMetadataKey, models.UpdateModel[models.CACertificate]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.Next.UpdateCAMetadata(ctx, input)
}

func (mw CAEventPublisher) DeleteCA(ctx context.Context, input services.DeleteCAInput) (err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventDeleteCAKey, input)
		}
	}()
	return mw.Next.DeleteCA(ctx, input)
}

func (mw CAEventPublisher) SignCertificate(ctx context.Context, input services.SignCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventSignCertificateKey, output)
		}
	}()
	return mw.Next.SignCertificate(ctx, input)
}

func (mw CAEventPublisher) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventCreateCertificateKey, output)
		}
	}()
	return mw.Next.CreateCertificate(ctx, input)
}

func (mw CAEventPublisher) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, "ca.certificate.import", output)
		}
	}()
	return mw.Next.ImportCertificate(ctx, input)
}

func (mw CAEventPublisher) SignatureSign(ctx context.Context, input services.SignatureSignInput) (output []byte, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventSignatureSignKey, output)
		}
	}()
	return mw.Next.SignatureSign(ctx, input)
}

func (mw CAEventPublisher) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (output bool, err error) {
	return mw.Next.SignatureVerify(ctx, input)
}

func (mw CAEventPublisher) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	return mw.Next.GetCertificateBySerialNumber(ctx, input)
}

func (mw CAEventPublisher) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	return mw.Next.GetCertificates(ctx, input)
}

func (mw CAEventPublisher) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	return mw.Next.GetCertificatesByCA(ctx, input)
}

func (mw CAEventPublisher) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	return mw.Next.GetCertificatesByExpirationDate(ctx, input)
}

func (mw CAEventPublisher) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (output *models.Certificate, err error) {
	prev, err := mw.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Certificate %s: %w", input.SerialNumber, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventUpdateCertificateStatusKey, models.UpdateModel[models.Certificate]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.Next.UpdateCertificateStatus(ctx, input)
}

func (mw CAEventPublisher) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	return mw.Next.GetCertificatesByCaAndStatus(ctx, input)
}

func (mw CAEventPublisher) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	return mw.Next.GetCertificatesByStatus(ctx, input)
}

func (mw CAEventPublisher) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (output *models.Certificate, err error) {
	prev, err := mw.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: input.SerialNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Certificate %s: %w", input.SerialNumber, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventUpdateCertificateMetadataKey, models.UpdateModel[models.Certificate]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.Next.UpdateCertificateMetadata(ctx, input)
}
