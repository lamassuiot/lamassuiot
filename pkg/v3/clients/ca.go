package clients

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
)

type CAClient services.CAService

type httpCAClient struct {
	httpClient *http.Client
	baseUrl    string
}

func NewHttpCAClient(client *http.Client, url string) services.CAService {
	baseURL := url
	return &httpCAClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *httpCAClient) GetCryptoEngineProvider() ([]*models.CryptoEngineProvider, error) {
	engine, err := Get[[]*models.CryptoEngineProvider](context.Background(), cli.httpClient, cli.baseUrl+"/v1/engines", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return engine, nil
}

func (cli *httpCAClient) GetCAs(input services.GetCAsInput) (string, error) {
	url := cli.baseUrl + "/v1/cas"

	if input.ExhaustiveRun {
		err := IterGet[models.CACertificate, *resources.GetCAsResponse](context.Background(), cli.httpClient, url, nil, input.ApplyFunc, map[int][]error{})
		return "", err
	} else {
		resp, err := Get[resources.GetCAsResponse](context.Background(), cli.httpClient, url, input.QueryParameters, map[int][]error{})
		return resp.NextBookmark, err
	}

}

func (cli *httpCAClient) GetCAByID(input services.GetCAByIDInput) (*models.CACertificate, error) {
	response, err := Get[models.CACertificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpCAClient) CreateCA(input services.CreateCAInput) (*models.CACertificate, error) {
	response, err := Post[*models.CACertificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas", resources.CreateCABody{
		Subject:            input.Subject,
		KeyMetadata:        input.KeyMetadata,
		CAType:             models.CAType(input.CAType),
		IssuanceExpiration: input.IssuanceExpiration,
		CAExpiration:       input.CAExpiration,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) ImportCA(input services.ImportCAInput) (*models.CACertificate, error) {
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
		CAType:             models.CAType(input.CAType),
		IssuanceExpiration: input.IssuanceExpiration,
		CACertificate:      input.CACertificate,
		CAChain:            input.CAChain,
		CAPrivateKey:       privKey,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) SignCertificate(input services.SignCertificateInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/certificates/sign", resources.SignCertificateBody{
		SignVerbatim: input.SignVerbatim,
		CertRequest:  input.CertRequest,
		Subject:      input.Subject,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) UpdateCAStatus(input services.UpdateCAStatusInput) (*models.CACertificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *httpCAClient) UpdateCAMetadata(input services.UpdateCAMetadataInput) (*models.CACertificate, error) {
	response, err := Post[*models.CACertificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/metadata", resources.UpdateCAMetadataBody{
		Metadata: input.Metadata,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) DeleteCA(input services.DeleteCAInput) error {
	return fmt.Errorf("TODO")
}

func (cli *httpCAClient) SignatureSign(input services.SignatureSignInput) ([]byte, error) {
	response, err := Post[*resources.SignResponse](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/signature/sign", resources.SignatureSignBody{
		Message:          base64.StdEncoding.EncodeToString(input.Message),
		MessageType:      input.MessageType,
		SigningAlgorithm: input.SigningAlgorithm,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(response.SignedData)
}

func (cli *httpCAClient) SignatureVerify(input services.SignatureVerifyInput) (bool, error) {
	response, err := Post[*resources.VerifyResponse](context.Background(), cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/signature/verify", resources.SignatureVerifyBody{
		Signature:        base64.StdEncoding.EncodeToString(input.Signature),
		Message:          base64.StdEncoding.EncodeToString(input.Message),
		MessageType:      input.MessageType,
		SigningAlgorithm: input.SigningAlgorithm,
	}, map[int][]error{})
	if err != nil {
		return false, err
	}

	return response.Valid, nil
}

func (cli *httpCAClient) GetCertificateBySerialNumber(input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	response, err := Get[*models.Certificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) GetCertificates(input services.GetCertificatesInput) (string, error) {
	return "", fmt.Errorf("TODO")
}

func (cli *httpCAClient) GetCertificatesByCA(input services.GetCertificatesByCAInput) (string, error) {
	url := cli.baseUrl + "/v1/cas/" + input.CAID + "/certificates"

	if input.ExhaustiveRun {
		err := IterGet[models.Certificate, *resources.GetCertsResponse](context.Background(), cli.httpClient, url, nil, input.ApplyFunc, map[int][]error{})
		return "", err
	} else {
		resp, err := Get[resources.GetCAsResponse](context.Background(), cli.httpClient, url, input.QueryParameters, map[int][]error{})
		return resp.NextBookmark, err
	}
}

func (cli *httpCAClient) GetCertificatesByExpirationDate(input services.GetCertificatesByExpirationDateInput) (string, error) {
	return "", fmt.Errorf("TODO")
}

func (cli *httpCAClient) UpdateCertificateStatus(input services.UpdateCertificateStatusInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber+"/status", resources.UpdateCertificateStatusBody{
		NewStatus: input.NewStatus,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil

}

func (cli *httpCAClient) UpdateCertificateMetadata(input services.UpdateCertificateMetadataInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](context.Background(), cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber+"/metadata", resources.UpdateCertificateMetadataBody{
		Metadata: input.Metadata,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}
