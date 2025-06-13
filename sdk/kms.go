package sdk

import (
	"context"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
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

func (cli *httpKMSClient) GetKeys(ctx context.Context) ([]*models.KeyInfo, error) {
	keys, err := Get[[]*models.KeyInfo](ctx, cli.httpClient, cli.baseUrl+"/v1/keys", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return keys, nil
}

func (cli *httpKMSClient) GetKeyByID(ctx context.Context, input services.GetByIDInput) (*models.KeyInfo, error) {
	response, err := Get[*models.KeyInfo](ctx, cli.httpClient, cli.baseUrl+"/v1/keys/"+input.ID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) CreateKey(ctx context.Context, input services.CreateKeyInput) (*models.KeyInfo, error) {
	response, err := Post[*models.KeyInfo](ctx, cli.httpClient, cli.baseUrl+"/v1/keys", resources.CreateKeyBody{
		Algorithm: input.Algorithm,
		Size:      input.Size,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) DeleteKeyByID(ctx context.Context, input services.GetByIDInput) error {
	err := Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/keys/"+input.ID, map[int][]error{})
	if err != nil {
		return err
	}

	return nil
}

func (cli *httpKMSClient) SignMessage(ctx context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	response, err := Post[*models.MessageSignature](ctx, cli.httpClient, cli.baseUrl+"/v1/keys/"+input.KeyID+"/sign", resources.SignMessageBody{
		Algorithm: input.Algorithm,
		Message:   input.Message,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) VerifySignature(ctx context.Context, input services.VerifySignInput) (bool, error) {
	response, err := Post[bool](ctx, cli.httpClient, cli.baseUrl+"/v1/keys/"+input.KeyID+"/verify", resources.VerifySignBody{
		Algorithm: input.Algorithm,
		Message:   input.Message,
		Signature: input.Signature,
	}, map[int][]error{})
	if err != nil {
		return false, err
	}

	return response, nil
}

func (cli *httpKMSClient) ImportKey(ctx context.Context, input services.ImportKeyInput) (*models.KeyInfo, error) {
	response, err := Post[*models.KeyInfo](ctx, cli.httpClient, cli.baseUrl+"/v1/keys/import", resources.ImportKeyBody{
		PrivateKey: input.PrivateKey,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}
