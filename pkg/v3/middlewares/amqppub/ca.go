package amqppub

import (
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

func (mw amqpEventPublisher) GetCryptoEngineProvider() ([]*models.CryptoEngineProvider, error) {
	return mw.next.GetCryptoEngineProvider()
}

func (mw amqpEventPublisher) CreateCA(input services.CreateCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.create", caSource, output)
		}
	}()
	return mw.next.CreateCA(input)
}

func (mw amqpEventPublisher) ImportCA(input services.ImportCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.import", caSource, output)
		}
	}()
	return mw.next.ImportCA(input)
}

func (mw amqpEventPublisher) GetCAByID(input services.GetCAByIDInput) (*models.CACertificate, error) {
	return mw.next.GetCAByID(input)
}

func (mw amqpEventPublisher) GetCAs(input services.GetCAsInput) (string, error) {
	return mw.next.GetCAs(input)
}

func (mw amqpEventPublisher) GetCAsByCommonName(input services.GetCAsByCommonNameInput) (string, error) {
	return mw.next.GetCAsByCommonName(input)
}

func (mw amqpEventPublisher) GetCABySerialNumber(input services.GetCABySerialNumberInput) (*models.CACertificate, error) {
	return mw.next.GetCABySerialNumber(input)
}

func (mw amqpEventPublisher) UpdateCAStatus(input services.UpdateCAStatusInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.update.status", caSource, output)
		}
	}()
	return mw.next.UpdateCAStatus(input)
}
func (mw amqpEventPublisher) UpdateCAMetadata(input services.UpdateCAMetadataInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.update.metadata", caSource, output)
		}
	}()
	return mw.next.UpdateCAMetadata(input)
}

func (mw amqpEventPublisher) DeleteCA(input services.DeleteCAInput) (err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.delete", caSource, input)
		}
	}()
	return mw.next.DeleteCA(input)
}

func (mw amqpEventPublisher) SignCertificate(input services.SignCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.certificate.sign", caSource, output)
		}
	}()
	return mw.next.SignCertificate(input)
}

func (mw amqpEventPublisher) SignatureSign(input services.SignatureSignInput) (output []byte, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.signature.sign", caSource, output)
		}
	}()
	return mw.next.SignatureSign(input)
}

func (mw amqpEventPublisher) SignatureVerify(input services.SignatureVerifyInput) (output bool, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("ca.signature.verify", caSource, output)
		}
	}()
	return mw.next.SignatureVerify(input)
}

func (mw amqpEventPublisher) GetCertificateBySerialNumber(input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	return mw.next.GetCertificateBySerialNumber(input)
}

func (mw amqpEventPublisher) GetCertificates(input services.GetCertificatesInput) (string, error) {
	return mw.next.GetCertificates(input)
}

func (mw amqpEventPublisher) GetCertificatesByCA(input services.GetCertificatesByCAInput) (string, error) {
	return mw.next.GetCertificatesByCA(input)
}

func (mw amqpEventPublisher) GetCertificatesByExpirationDate(input services.GetCertificatesByExpirationDateInput) (string, error) {
	return mw.next.GetCertificatesByExpirationDate(input)
}

func (mw amqpEventPublisher) UpdateCertificateStatus(input services.UpdateCertificateStatusInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("certificate.update.status", caSource, output)
		}
	}()
	return mw.next.UpdateCertificateStatus(input)
}

func (mw amqpEventPublisher) UpdateCertificateMetadata(input services.UpdateCertificateMetadataInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent("certificate.update.metadata", caSource, output)
		}
	}()
	return mw.next.UpdateCertificateMetadata(input)
}
