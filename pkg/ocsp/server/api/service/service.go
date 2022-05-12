package service

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/secrets"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/crypto/ocsp"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/secrets/responder"
)

type Service interface {
	Health(ctx context.Context) bool
	Verify(ctx context.Context, msg []byte) ([]byte, error)
}

type OCSPResponder struct {
	lamassuCAClient client.LamassuCaClient
	respSecrets     responder.Secrets
	respCert        *x509.Certificate
	nonceList       [][]byte
}

func NewService(respSecrets responder.Secrets, lamassuCAClient *client.LamassuCaClient) (Service, error) {
	//the certs should not change, so lets keep them in memory

	respcert, err := respSecrets.GetResponderCert()
	if err != nil {
		return nil, err
	}
	responder := &OCSPResponder{
		lamassuCAClient: *lamassuCAClient,
		respSecrets:     respSecrets,
		respCert:        respcert,
	}

	return responder, nil
}

func (o *OCSPResponder) verifyIssuer(req *ocsp.Request, ca x509.Certificate) error {

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
	var status int
	var revokedAt time.Time

	// parse the request
	req, exts, err := ocsp.ParseRequest(msg)
	if err != nil {
		return nil, err
	}

	cas, err := o.lamassuCAClient.GetCAs(context.Background(), dto.Pki)
	if err != nil {
		return nil, errors.New("Could not get CAs")
	}
	var issuerCA dto.Cert
	var x509Certificate *x509.Certificate
	//make sure the request is valid
	for _, ca := range cas {
		data, _ := base64.StdEncoding.DecodeString(ca.CertContent.CerificateBase64)
		block, _ := pem.Decode([]byte(data))
		x509Certificate, _ := x509.ParseCertificate(block.Bytes)

		err = o.verifyIssuer(req, *x509Certificate)
		if err != nil {
			continue
		} else {
			issuerCA = ca
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if issuerCA.Status != secrets.StatusValid {
		fmt.Println("Issuing CA is not valid")
	}

	cert, err := o.lamassuCAClient.GetCert(context.Background(), dto.Pki, issuerCA.Name, req.SerialNumber.String())
	if err != nil {
		return nil, errors.New("Could not get certificate")
	}

	if err != nil {
		status = ocsp.Unknown
	} else {
		if cert.Status == secrets.StatusRevoked || cert.Status == secrets.StatusExpired {
			status = ocsp.Revoked
			tm := time.Unix(cert.RevocationTimestamp, 0)
			revokedAt = tm
		} else if cert.Status == secrets.StatusValid {
			status = ocsp.Good
		}
	}

	// parse key file
	// perhaps I should zero this out after use
	keyi, err := o.respSecrets.GetResponderKey()
	if err != nil {
		return nil, err
	}
	key, ok := keyi.(crypto.Signer)
	if !ok {
		return nil, errors.New("Could not make key a signer")
	}

	// check for nonce extension
	var responseExtensions []pkix.Extension
	nonce := checkForNonceExtension(exts)

	// check if the nonce has been used before
	if o.nonceList == nil {
		o.nonceList = make([][]byte, 10)
	}

	if nonce != nil {
		for _, n := range o.nonceList {
			if bytes.Compare(n, nonce.Value) == 0 {
				return nil, errors.New("This nonce has already been used")
			}
		}

		o.nonceList = append(o.nonceList, nonce.Value)
		responseExtensions = append(responseExtensions, *nonce)
	}

	// construct response template
	rtemplate := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		Certificate:      o.respCert,
		RevocationReason: ocsp.Unspecified,
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revokedAt,
		ThisUpdate:       time.Now().AddDate(0, 0, -1).UTC(),
		//adding 1 day after the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		NextUpdate: time.Now().AddDate(0, 0, 1).UTC(),
		Extensions: exts,
	}

	// make a response to return
	resp, err := ocsp.CreateResponse(x509Certificate, o.respCert, rtemplate, key)
	if err != nil {
		return nil, err
	}
	return resp, nil

}

// takes a list of extensions and returns the nonce extension if it is present
func checkForNonceExtension(exts []pkix.Extension) *pkix.Extension {
	nonce_oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	for _, ext := range exts {
		if ext.Id.Equal(nonce_oid) {
			return &ext
		}
	}
	return nil
}
