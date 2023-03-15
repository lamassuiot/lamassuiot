package clients

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

type caClient struct {
	httpClient http.Client
	baseUrl    string
}

func NewCAClient(client http.Client, url string) services.CAService {
	baseURL := url
	return &caClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *caClient) GetCryptoEngineProviders() []models.EngineProvider {
	engines, err := Get[[]models.EngineProvider](context.Background(), cli.baseUrl+"/v1/engines", nil)
	if err != nil {
		fmt.Println(err)
		return []models.EngineProvider{}
	}

	return engines
}

func (cli *caClient) GetCAs(input services.GetCAsInput) (string, error) {
	url := cli.baseUrl + "/v1/cas"

	if input.ExhaustiveRun {
		err := IterGet[models.CACertificate, *resources.GetCAsResponse](context.Background(), url, nil, input.ApplyFunc)
		return "", err
	} else {
		resp, err := Get[resources.GetCAsResponse](context.Background(), url, input.QueryParameters)
		return resp.NextBookmark, err
	}

}

func (cli *caClient) GetCAByID(input services.GetCAByIDInput) (*models.CACertificate, error) {
	response, err := Get[models.CACertificate](context.Background(), cli.baseUrl+"/v1/ca/"+input.ID, nil)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *caClient) CreateCA(input services.CreateCAInput) (*models.CACertificate, error) {
	response, err := Post[*models.CACertificate](context.Background(), cli.baseUrl+"/v1/cas", resources.CreateCABody{
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

func (cli *caClient) SignCertificate(input services.SignCertificateInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](context.Background(), cli.baseUrl+"/v1/cas/"+input.CAID+"/sign", resources.SignCertificateBody{
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
	response, err := Get[*models.Certificate](context.Background(), cli.baseUrl+"/v1/certificates/"+input.SerialNumber, nil)
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
