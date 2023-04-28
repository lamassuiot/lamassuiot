package clients

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

type caClient struct {
	httpClient *http.Client
	baseUrl    string
}

func NewCAClient(client *http.Client, url string) services.CAService {
	baseURL := url
	return &caClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *caClient) GetCryptoEngineProvider() (*models.EngineProvider, error) {
	engine, err := Get[models.EngineProvider](context.Background(), cli.httpClient, cli.baseUrl+"/v1/engines", nil)
	if err != nil {
		return nil, err
	}

	return &engine, nil
}

func (cli *caClient) Sign(input services.SignInput) ([]byte, error) {
	response, err := Post[*resources.SignResponse](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/sign", resources.SignBody{
		Message:            base64.StdEncoding.EncodeToString(input.Message),
		MessageType:        input.MessageType,
		SignatureAlgorithm: input.SignatureAlgorithm,
	})
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(response.SignedData)
}

func (cli *caClient) VerifySignature(input services.VerifySignatureInput) (bool, error) {
	response, err := Post[*resources.VerifyResponse](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/verify", resources.VerifyBody{
		Message:            base64.StdEncoding.EncodeToString(input.Message),
		MessageType:        input.MessageType,
		SignatureAlgorithm: input.SignatureAlgorithm,
		Signature:          base64.StdEncoding.EncodeToString(input.Signature),
	})
	if err != nil {
		return false, err
	}

	return response.Valid, nil
}

func (cli *caClient) GetCAs(input services.GetCAsInput) (string, error) {
	url := cli.baseUrl + "/v1/cas"

	if input.ExhaustiveRun {
		err := IterGet[models.CACertificate, *resources.GetCAsResponse](context.Background(), cli.httpClient, url, nil, input.ApplyFunc)
		return "", err
	} else {
		resp, err := Get[resources.GetCAsResponse](context.Background(), cli.httpClient, url, input.QueryParameters)
		return resp.NextBookmark, err
	}

}

func (cli *caClient) GetCAByID(input services.GetCAByIDInput) (*models.CACertificate, error) {
	response, err := Get[models.CACertificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID, nil)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *caClient) CreateCA(input services.CreateCAInput) (*models.CACertificate, error) {
	response, err := Post[*models.CACertificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas", resources.CreateCABody{
		Subject:            input.Subject,
		KeyMetadata:        input.KeyMetadata,
		CAType:             models.CAType(input.CAType),
		IssuanceDuration:   models.TimeDuration(input.IssuanceDuration),
		CAVailidtyDurarion: models.TimeDuration(input.CADuration),
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *caClient) ImportCA(input services.ImportCAInput) (*models.CACertificate, error) {
	var privKey string
	if input.KeyType == models.KeyType(x509.RSA) {
		rsaBytes := x509.MarshalPKCS1PrivateKey(input.CARSAKey)
		privKey = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: rsaBytes,
		}))
	} else if input.KeyType == models.KeyType(x509.ECDSA) {
		ecBytes, err := x509.MarshalECPrivateKey(input.CAECKey)
		if err != nil {
			return nil, err
		}
		privKey = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecBytes,
		}))
	}

	response, err := Post[*models.CACertificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas/import", resources.ImportCABody{
		CAType:           models.CAType(input.CAType),
		IssuanceDuration: models.TimeDuration(input.IssuanceDuration),
		CACertificate:    input.CACertificate,
		CAChain:          input.CAChain,
		CAPrivateKey:     privKey,
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *caClient) SignCertificate(input services.SignCertificateInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/sign-cert", resources.SignCertificateBody{
		SignVerbatim: input.SignVerbatim,
		CertRequest:  input.CertRequest,
		Subject:      input.Subject,
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *caClient) UpdateCAStatus(input services.UpdateCAStatusInput) (*models.CACertificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *caClient) DeleteCA(input services.DeleteCAInput) error {
	return fmt.Errorf("TODO")
}

func (cli *caClient) GetCertificateBySerialNumber(input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	response, err := Get[*models.Certificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber, nil)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *caClient) GetCertificates(input services.GetCertificatesInput) (string, error) {
	return "", fmt.Errorf("TODO")
}

func (cli *caClient) GetCertificatesByCA(input services.GetCertificatesByCAInput) (string, error) {
	return "", fmt.Errorf("TODO")
}

func (cli *caClient) GetCertificatesByExpirationDate(input services.GetCertificatesByExpirationDateInput) (string, error) {
	return "", fmt.Errorf("TODO")
}

func (cli *caClient) UpdateCertificateStatus(input services.UpdateCertificateStatusInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber+"/status", resources.UpdateCertificateStatusBody{
		NewStatus:        input.NewStatus,
		RevocationReason: input.RevocationReason,
	})
	if err != nil {
		return nil, err
	}

	return response, nil

}
