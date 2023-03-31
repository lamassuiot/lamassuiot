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
	HttpClient *http.Client
	baseUrl    string
}

func NewCAClient(client *http.Client, url string) services.CAService {
	baseURL := url
	return &caClient{
		HttpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *caClient) GetCryptoEngineProviders() []models.EngineProvider {
	engines, err := Get[[]models.EngineProvider](context.Background(), cli.HttpClient, cli.baseUrl+"/v1/engines", nil)
	if err != nil {
		fmt.Println(err)
		return []models.EngineProvider{}
	}

	return engines
}

func (cli *caClient) GetCAs(input services.GetCAsInput) (string, error) {
	url := cli.baseUrl + "/v1/cas"

	if input.ExhaustiveRun {
		err := IterGet[models.CACertificate, *resources.GetCAsResponse](context.Background(), cli.HttpClient, url, nil, input.ApplyFunc)
		return "", err
	} else {
		resp, err := Get[resources.GetCAsResponse](context.Background(), cli.HttpClient, url, input.QueryParameters)
		return resp.NextBookmark, err
	}

}

func (cli *caClient) GetCAByID(input services.GetCAByIDInput) (*models.CACertificate, error) {
	response, err := Get[models.CACertificate](context.Background(), cli.HttpClient, cli.baseUrl+"/v1/ca/"+input.ID, nil)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *caClient) CreateCA(input services.CreateCAInput) (*models.CACertificate, error) {
	response, err := Post[*models.CACertificate](context.Background(), cli.HttpClient, cli.baseUrl+"/v1/cas", resources.CreateCABody{
		EngineID:           input.EngineID,
		IssuerCAID:         input.IssuerCAID,
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
	if input.KeyType == models.RSA {
		rsaBytes := x509.MarshalPKCS1PrivateKey(input.CARSAKey)
		privKey = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: rsaBytes,
		}))
	} else if input.KeyType == models.ECDSA {
		ecBytes, err := x509.MarshalECPrivateKey(input.CAECKey)
		if err != nil {
			return nil, err
		}
		privKey = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecBytes,
		}))
	}

	response, err := Post[*models.CACertificate](context.Background(), cli.HttpClient, cli.baseUrl+"/v1/cas/import", resources.ImportCABody{
		EngineID:         input.EngineID,
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
	response, err := Post[*models.Certificate](context.Background(), cli.HttpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/sign", resources.SignCertificateBody{
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

func (cli *caClient) RotateCA(input services.RotateCAInput) (*models.CACertificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *caClient) DeleteCA(input services.DeleteCAInput) error {
	return fmt.Errorf("TODO")
}

func (cli *caClient) GetCertificateBySerialNumber(input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	response, err := Get[*models.Certificate](context.Background(), cli.HttpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber, nil)
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
	return nil, fmt.Errorf("TODO")
}
