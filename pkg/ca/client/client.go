package client

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	clientFilers "github.com/lamassuiot/lamassuiot/pkg/utils/client/filters"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type LamassuCaClient interface {
	GetCAs(ctx context.Context, caType dto.CAType, queryparameters filters.QueryParameters) (dto.GetCasResponse, error)
	CreateCA(ctx context.Context, caType dto.CAType, caName string, privateKeyMetadata dto.PrivateKeyMetadata, subject dto.Subject, caTTL time.Duration, enrollerTTL time.Duration) (dto.Cert, error)
	ImportCA(ctx context.Context, caType dto.CAType, caName string, certificate x509.Certificate, privateKey dto.PrivateKey, enrollerTTL time.Duration) (dto.Cert, error)
	DeleteCA(ctx context.Context, caType dto.CAType, caName string) error

	SignCertificateRequest(ctx context.Context, caType dto.CAType, caName string, csr *x509.CertificateRequest, signVerbatim bool, cn string) (*x509.Certificate, *x509.Certificate, error)
	RevokeCert(ctx context.Context, caType dto.CAType, caName string, serialNumberToRevoke string) error
	GetCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) (dto.Cert, error)
	GetIssuedCerts(ctx context.Context, caType dto.CAType, caName string, queryParameters filters.QueryParameters) (dto.IssuedCertsResponse, error)
}

type lamassuCaClientConfig struct {
	client clientUtils.BaseClient
}

func NewLamassuCAClient(config clientUtils.ClientConfiguration) (LamassuCaClient, error) {
	baseClient, err := clientUtils.NewBaseClient(config)
	if err != nil {
		return nil, err
	}

	return &lamassuCaClientConfig{
		client: baseClient,
	}, nil
}

func (c *lamassuCaClientConfig) GetCAs(ctx context.Context, caType dto.CAType, queryparameters filters.QueryParameters) (dto.GetCasResponse, error) {
	req, err := c.client.NewRequest("GET", "v1/"+caType.String(), nil)
	if err != nil {
		return dto.GetCasResponse{}, err
	}

	newParams := clientFilers.GenerateHttpQueryParams(queryparameters)
	req.URL.RawQuery = newParams

	respBody, _, err := c.client.Do(req)
	if err != nil {
		return dto.GetCasResponse{}, err
	}

	var cas dto.GetCasResponse
	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &cas)

	return cas, nil
}

func (c *lamassuCaClientConfig) CreateCA(ctx context.Context, caType dto.CAType, caName string, privateKeyMetadata dto.PrivateKeyMetadata, subject dto.Subject, caTTL time.Duration, enrollerTTL time.Duration) (dto.Cert, error) {
	body := &dto.CreateCARequestPayload{
		CaTTL:       int(caTTL.Hours()),
		EnrollerTTL: int(enrollerTTL.Hours()),
		KeyMetadata: dto.PrivateKeyMetadata{
			KeyType: privateKeyMetadata.KeyType,
			KeyBits: privateKeyMetadata.KeyBits,
		},
		Subject: dto.Subject{
			CommonName:       subject.CommonName,
			Organization:     subject.Organization,
			OrganizationUnit: subject.OrganizationUnit,
			Country:          subject.Country,
			State:            subject.State,
			Locality:         subject.Locality,
		},
	}

	req, err := c.client.NewRequest("POST", "v1/pki/"+caName, body)
	if err != nil {
		return dto.Cert{}, err
	}
	respBody, _, err := c.client.Do(req)
	if err != nil {
		return dto.Cert{}, err
	}

	var cert dto.Cert

	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &cert)
	return cert, nil
}

func (c *lamassuCaClientConfig) ImportCA(ctx context.Context, caType dto.CAType, caName string, certificate x509.Certificate, privateKey dto.PrivateKey, enrollerTTL time.Duration) (dto.Cert, error) {
	crtBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	base64CrtContent := base64.StdEncoding.EncodeToString(crtBytes)
	privKeyString, _ := privateKey.GetPEMString()
	base64CKeyContent := base64.StdEncoding.EncodeToString([]byte(privKeyString))
	body := &dto.ImportCARequestPayload{
		Crt:         base64CrtContent,
		EnrollerTTL: int(enrollerTTL.Hours()),
		PrivateKey:  base64CKeyContent,
	}

	req, err := c.client.NewRequest("POST", "v1/"+caType.String()+"/import/"+caName, body)
	if err != nil {
		return dto.Cert{}, err
	}
	respBody, _, err := c.client.Do(req)
	if err != nil {
		return dto.Cert{}, err
	}

	var cert dto.Cert

	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &cert)
	return cert, nil
}

func (c *lamassuCaClientConfig) DeleteCA(ctx context.Context, caType dto.CAType, caName string) error {

	req, err := c.client.NewRequest("DELETE", "v1/"+caType.String()+"/"+caName, nil)
	if err != nil {
		return err
	}
	_, _, err = c.client.Do(req)
	if err != nil {
		return err
	}
	return nil
}

func (c *lamassuCaClientConfig) SignCertificateRequest(ctx context.Context, caType dto.CAType, caName string, csr *x509.CertificateRequest, signVerbatim bool, cn string) (*x509.Certificate, *x509.Certificate, error) {
	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	base64CsrContent := base64.StdEncoding.EncodeToString(csrBytes)
	body := &dto.SignPayload{
		Csr:          base64CsrContent,
		CommonName:   cn,
		SignVerbatim: signVerbatim,
	}
	req, err := c.client.NewRequest("POST", "v1/"+caType.String()+"/"+caName+"/sign", body)

	if err != nil {
		return nil, nil, err
	}
	respBody, _, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	var cert dto.SignResponse

	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &cert)

	data, _ := base64.StdEncoding.DecodeString(cert.Crt)
	block, _ := pem.Decode([]byte(data))
	x509Certificate, _ := x509.ParseCertificate(block.Bytes)
	data, _ = base64.StdEncoding.DecodeString(cert.CaCrt)
	block, _ = pem.Decode([]byte(data))
	caCrt, _ := x509.ParseCertificate(block.Bytes)

	return x509Certificate, caCrt, nil
}

func (c *lamassuCaClientConfig) RevokeCert(ctx context.Context, caType dto.CAType, caName string, serialNumberToRevoke string) error {

	req, err := c.client.NewRequest("DELETE", "v1/"+caType.String()+"/"+caName+"/cert/"+serialNumberToRevoke, nil)
	if err != nil {
		return err
	}
	_, resp, err := c.client.Do(req)
	if resp.StatusCode == 412 {
		return &AlreadyRevokedError{
			CaName:       caName,
			SerialNumber: serialNumberToRevoke,
		}
	} else if err != nil {
		return err
	} else {

		return nil
	}

}

func (c *lamassuCaClientConfig) GetCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) (dto.Cert, error) {

	req, err := c.client.NewRequest("GET", "v1/"+caType.String()+"/"+caName+"/cert/"+serialNumber, nil)
	if err != nil {
		return dto.Cert{}, err
	}
	respBody, _, err := c.client.Do(req)
	if err != nil {
		return dto.Cert{}, err
	}

	var cert dto.Cert
	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &cert)

	return cert, nil

}

func (c *lamassuCaClientConfig) GetIssuedCerts(ctx context.Context, caType dto.CAType, caName string, queryParameters filters.QueryParameters) (dto.IssuedCertsResponse, error) {
	req, err := c.client.NewRequest("GET", "v1/"+caType.String()+"/"+caName+"/issued", nil)
	if err != nil {
		return dto.IssuedCertsResponse{}, err
	}

	newParams := clientFilers.GenerateHttpQueryParams(queryParameters)
	req.URL.RawQuery = newParams

	respBody, _, err := c.client.Do(req)
	if err != nil {
		return dto.IssuedCertsResponse{}, err
	}

	var cert dto.IssuedCertsResponse
	jsonString, _ := json.Marshal(respBody)
	json.Unmarshal(jsonString, &cert)

	return cert, nil
}

type AlreadyRevokedError struct {
	CaName       string
	SerialNumber string
}
type AlreadyRevokedCAError struct {
	CaName string
}

func (e *AlreadyRevokedError) Error() string {
	return fmt.Sprintf("certificate already revoked. CA name=%s Cert Serial Number=%s", e.CaName, e.SerialNumber)
}

func (e *AlreadyRevokedCAError) Error() string {
	return fmt.Sprintf("CA already revoked: %s", e.CaName)
}
