package amqppub

import (
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

type amqpEventPublisher struct {
	next          services.CAService
	amqpPublisher chan *AmqpPublishMessage
}

const caSource = "lamassuiot.ca"

func NewCAAmqpEventPublisher(amqpPublisher chan *AmqpPublishMessage) services.CAMiddleware {
	return func(next services.CAService) services.CAService {
		return &amqpEventPublisher{
			next:          next,
			amqpPublisher: amqpPublisher,
		}
	}
}

func (mw amqpEventPublisher) GetCryptoEngineProvider() (*models.EngineProvider, error) {
	return mw.next.GetCryptoEngineProvider()
}

func (mw amqpEventPublisher) CreateCA(input services.CreateCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.publishEvent("ca.create", caSource, output)
		}
	}()
	return mw.next.CreateCA(input)
}

func (mw amqpEventPublisher) Sign(input services.SignInput) (output []byte, err error) {
	return mw.next.Sign(input)
}
func (mw amqpEventPublisher) VerifySignature(input services.VerifySignatureInput) (bool, error) {
	return mw.next.VerifySignature(input)
}

func (mw amqpEventPublisher) ImportCA(input services.ImportCAInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.publishEvent("ca.import", caSource, output)
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

func (mw amqpEventPublisher) UpdateCAStatus(input services.UpdateCAStatusInput) (output *models.CACertificate, err error) {
	defer func() {
		if err == nil {
			mw.publishEvent("ca.update", caSource, output)
		}
	}()
	return mw.next.UpdateCAStatus(input)
}

func (mw amqpEventPublisher) DeleteCA(input services.DeleteCAInput) (err error) {
	defer func() {
		if err == nil {
			mw.publishEvent("ca.delete", caSource, input)
		}
	}()
	return mw.next.DeleteCA(input)
}

func (mw amqpEventPublisher) SignCertificate(input services.SignCertificateInput) (output *models.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.publishEvent("ca.sign-certificate", caSource, output)
		}
	}()
	return mw.next.SignCertificate(input)
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
			mw.publishEvent("certificate.update", caSource, output)
		}
	}()
	return mw.next.UpdateCertificateStatus(input)
}
