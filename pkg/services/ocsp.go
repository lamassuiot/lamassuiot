package services

import (
	"crypto"
	"crypto/x509"
	"io"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"golang.org/x/crypto/ocsp"
)

type OCSPServiceMiddleware func(CAService) OCSPService

type OCSPService interface {
	Validate(input *ocsp.Request) ([]byte, error)
}

type OCSPServiceImpl struct {
	caService CAService
}

type OCSPServiceBuilder struct {
	CAClient CAService
}

func NeOCSPervice(builder OCSPServiceBuilder) OCSPService {
	validate = validator.New()

	svc := OCSPServiceImpl{
		caService: builder.CAClient,
	}

	return &svc
}

func (svc *OCSPServiceImpl) Validate(input *ocsp.Request) ([]byte, error) {
	sn := helpers.SerialNumberToString(input.SerialNumber)
	cert, err := svc.caService.GetCertificateBySerialNumber(GetCertificatesBySerialNumberInput{
		SerialNumber: sn,
	})

	if err != nil {
		return nil, err
	}

	// construct response template
	rtemplate := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: input.SerialNumber,
		Certificate:  (*x509.Certificate)(cert.Certificate),
		ThisUpdate:   time.Now().AddDate(0, 0, -1).UTC(),
		//adding 1 day after the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		NextUpdate: time.Now().AddDate(0, 0, 1).UTC(),
	}

	if cert.Status == models.StatusRevoked {
		rtemplate.Status = ocsp.Revoked
		rtemplate.RevokedAt = cert.RevocationTimestamp
		rtemplate.RevocationReason = int(cert.RevocationReason)
	}

	signer, caCert, err := NewRemoteSigner(svc.caService, cert.IssuerCAMetadata.CAID)
	if err != nil {
		return nil, err
	}

	// make a response to return
	resp, err := ocsp.CreateResponse(caCert, (*x509.Certificate)(cert.Certificate), rtemplate, signer)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

type remoteCASigner struct {
	caClient      CAService
	caID          string
	caCertificate *models.X509Certificate
}

func NewRemoteSigner(caClient CAService, caID string) (crypto.Signer, *x509.Certificate, error) {
	ca, err := caClient.GetCAByID(GetCAByIDInput{
		CAID: caID,
	})
	if err != nil {
		return nil, nil, err
	}

	return &remoteCASigner{
		caClient:      caClient,
		caID:          caID,
		caCertificate: ca.Certificate.Certificate,
	}, (*x509.Certificate)(ca.Certificate.Certificate), nil
}

func (remSigner *remoteCASigner) Public() crypto.PublicKey {
	return remSigner.caCertificate.PublicKey
}

func (remSigner *remoteCASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	algo, err := helpers.GetSigningAlgorithmFromPublicKey(remSigner.Public(), opts.HashFunc())
	if err != nil {
		return nil, err
	}

	return remSigner.caClient.Sign(SignInput{
		CAID:               remSigner.caID,
		Message:            digest,
		MessageType:        models.Digest,
		SignatureAlgorithm: algo,
	})
}
