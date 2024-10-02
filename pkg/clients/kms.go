package clients

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"

	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

type KMSClient services.KMSService

type httpKMSClient struct {
	httpClient *http.Client
	baseUrl    string
}

func NewHttpKMSClient(client *http.Client, url string) services.KMSService {
	baseURL := url
	return &httpKMSClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *httpKMSClient) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	engine, err := Get[[]*models.CryptoEngineProvider](ctx, cli.httpClient, cli.baseUrl+"/v1/engines", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return engine, nil
}

func (cli *httpKMSClient) CreatePrivateKey(ctx context.Context, input services.CreatePrivateKeyInput) (*models.AsymmetricCryptoKey, error) {
	response, err := Post[*models.AsymmetricCryptoKey](ctx, cli.httpClient, cli.baseUrl+"/v1/", resources.CreatePrivateKeyBody{
		EngineID:     input.EngineID,
		KeyAlgorithm: input.KeyAlgorithm,
		KeySize:      input.KeySize,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) ImportPrivateKey(ctx context.Context, input services.ImportPrivateKeyInput) (*models.AsymmetricCryptoKey, error) {
	var err error
	key := ""
	if input.KeyType == models.KeyType(x509.RSA) {
		key, err = helpers.PrivateKeyToPEM(input.RSAKey)
		if err != nil {
			return nil, err
		}
	} else {
		key, err = helpers.PrivateKeyToPEM(input.ECKey)
		if err != nil {
			return nil, err
		}
	}

	response, err := Post[*models.AsymmetricCryptoKey](ctx, cli.httpClient, cli.baseUrl+"/v1/import", resources.ImportPrivateKey{
		EngineID:   input.EngineID,
		PrivateKey: key,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil

}

func (cli *httpKMSClient) GetKey(ctx context.Context, input services.GetKeyInput) (*models.AsymmetricCryptoKey, error) {
	url := cli.baseUrl + "/v1/" + input.EngineID + "/" + input.KeyID
	if input.EngineID == "" {
		url = cli.baseUrl + "/v1/" + input.KeyID
	}
	response, err := Get[models.AsymmetricCryptoKey](ctx, cli.httpClient, url, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpKMSClient) Sign(ctx context.Context, input services.SignInput) (signature []byte, err error) {
	response, err := Post[*resources.SignResponse](ctx, cli.httpClient, cli.baseUrl+"/v1/"+input.EngineID+"/"+input.KeyID+"/sign", resources.SignatureSignBody{
		Message:          base64.StdEncoding.EncodeToString(input.Message),
		MessageType:      input.MessageType,
		SigningAlgorithm: input.SigningAlgorithm,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(response.SignedData)

}

func (cli *httpKMSClient) Verify(ctx context.Context, input services.VerifyInput) (bool, error) {
	response, err := Post[*resources.VerifyResponse](ctx, cli.httpClient, cli.baseUrl+"/v1/"+input.EngineID+"/"+input.KeyID+"/verify", resources.SignatureVerifyBody{
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
