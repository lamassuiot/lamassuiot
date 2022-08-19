package service

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"golang.org/x/crypto/ocsp"
)

type Service interface {
	Health(ctx context.Context) bool
	Verify(ctx context.Context, msg []byte) ([]byte, error)
}

type OCSPResponder struct {
	lamassuCAClient      client.LamassuCAClient
	responderSigner      crypto.Signer
	responderCertificate *x509.Certificate
}

func NewOCSPService(lamassuCAClient client.LamassuCAClient, key crypto.Signer, certificate *x509.Certificate) Service {
	responder := &OCSPResponder{
		lamassuCAClient:      lamassuCAClient,
		responderSigner:      key,
		responderCertificate: certificate,
	}

	return responder
}

func (o *OCSPResponder) verifyIssuer(req *ocsp.Request, ca *x509.Certificate) error {

	h := req.HashAlgorithm.New()
	h.Write(ca.RawSubject)
	if bytes.Compare(h.Sum(nil), req.IssuerNameHash) != 0 {
		return errors.New("Issuer name does not match")
	}

	h.Reset()
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(ca.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return err
	}

	h.Write(publicKeyInfo.PublicKey.RightAlign())
	if bytes.Compare(h.Sum(nil), req.IssuerKeyHash) != 0 {
		return errors.New("Issuer key hash does not match")
	}

	return nil
}

func (o *OCSPResponder) Health(ctx context.Context) bool {
	return true
}

func (o *OCSPResponder) Verify(ctx context.Context, msg []byte) ([]byte, error) {
	var issuerCA *api.CACertificate

	var status int
	var revokedAt time.Time

	// parse the request
	req, err := ocsp.ParseRequest(msg)

	_, err = o.lamassuCAClient.IterateCAsWithPredicate(ctx, &api.IterateCAsWithPredicateInput{
		CAType: api.CATypePKI,
		PredicateFunc: func(ca *api.CACertificate) {
			err = o.verifyIssuer(req, ca.Certificate.Certificate)
			if err == nil {
				issuerCA = ca
			}
		},
	})
	if err != nil {
		return nil, err
	}

	if issuerCA == nil {
		return nil, errors.New("Issuer CA not found")
	}

	if issuerCA.Status == api.StatusExpired || issuerCA.Status == api.StatusRevoked {
		return nil, errors.New("Issuing CA is not valid")
	}

	cert, err := o.lamassuCAClient.GetCertificateBySerialNumber(ctx, &api.GetCertificateBySerialNumberInput{
		CAType:                  api.CATypePKI,
		CAName:                  issuerCA.CAName,
		CertificateSerialNumber: utils.InsertNth(utils.ToHexInt(req.SerialNumber), 2),
	})

	if err != nil {
		return nil, errors.New("Could not get certificate")
	}

	if err != nil {
		status = ocsp.Unknown
	} else {
		if cert.Status == api.StatusRevoked {
			status = ocsp.Revoked
			revokedAt = cert.RevocationTimestamp.Time
		} else if cert.Status == api.StatusIssued || cert.Status == api.StatusAboutToExpire {
			status = ocsp.Good
		}
	}

	// construct response template
	rtemplate := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		Certificate:      o.responderCertificate,
		RevocationReason: ocsp.Unspecified,
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revokedAt,
		ThisUpdate:       time.Now().AddDate(0, 0, -1).UTC(),
		//adding 1 day after the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		NextUpdate: time.Now().AddDate(0, 0, 1).UTC(),
	}

	// make a response to return
	resp, err := ocsp.CreateResponse(issuerCA.Certificate.Certificate, o.responderCertificate, rtemplate, o.responderSigner)
	if err != nil {
		return nil, err
	}
	return resp, nil

}
