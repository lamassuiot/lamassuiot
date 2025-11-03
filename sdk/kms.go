package sdk

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
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

func (cli *httpKMSClient) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	engine, err := Get[[]*models.CryptoEngineProvider](ctx, cli.httpClient, cli.baseUrl+"/v1/engines", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return engine, nil
}

func (cli *httpKMSClient) GetKeys(ctx context.Context, input services.GetKeysInput) (string, error) {
	url := cli.baseUrl + "/v1/keys"
	return IterGet[models.Key, *resources.GetKeysResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpKMSClient) GetKey(ctx context.Context, input services.GetKeyInput) (*models.Key, error) {
	response, err := Get[models.Key](ctx, cli.httpClient, cli.baseUrl+"/v1/keys/"+input.Identifier, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpKMSClient) CreateKey(ctx context.Context, input services.CreateKeyInput) (*models.Key, error) {
	response, err := Post[*models.Key](ctx, cli.httpClient, cli.baseUrl+"/v1/keys", resources.CreateKeyBody{
		Algorithm: input.Algorithm,
		Size:      input.Size,
		EngineID:  input.EngineID,
		Name:      input.Name,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) ImportKey(ctx context.Context, input services.ImportKeyInput) (*models.Key, error) {
	keyPem, err := helpers.PrivateKeyToPEM(input.PrivateKey)
	if err != nil {
		return nil, err
	}

	keyB64 := base64.StdEncoding.EncodeToString([]byte(keyPem))

	response, err := Post[*models.Key](ctx, cli.httpClient, cli.baseUrl+"/v1/keys/import", resources.ImportKeyBody{
		PrivateKey: keyB64,
		EngineID:   input.EngineID,
		Name:       input.Name,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) UpdateKeyMetadata(ctx context.Context, input services.UpdateKeyMetadataInput) (*models.Key, error) {
	response, err := Put[*models.Key](ctx, cli.httpClient, cli.baseUrl+"/v1/keys/"+input.ID+"/metadata", resources.UpdateKeyMetadataBody{
		Patches: input.Patches,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) UpdateKeyAliases(ctx context.Context, input services.UpdateKeyAliasesInput) (*models.Key, error) {
	response, err := Put[*models.Key](ctx, cli.httpClient, cli.baseUrl+"/v1/keys/"+input.ID+"/aliases", resources.UpdateKeyAliasesBody{
		Patches: input.Patches,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) UpdateKeyName(ctx context.Context, input services.UpdateKeyNameInput) (*models.Key, error) {
	response, err := Put[*models.Key](ctx, cli.httpClient, cli.baseUrl+"/v1/keys/"+input.ID+"/name", resources.UpdateKeyNameBody{
		Name: input.Name,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) DeleteKeyByID(ctx context.Context, input services.GetKeyInput) error {
	err := Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/keys/"+input.Identifier, map[int][]error{})
	if err != nil {
		return err
	}

	return nil
}

func (cli *httpKMSClient) SignMessage(ctx context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	response, err := Post[*models.MessageSignature](ctx, cli.httpClient, cli.baseUrl+"/v1/keys/"+input.Identifier+"/sign", resources.SignMessageBody{
		Algorithm:   input.Algorithm,
		Message:     input.Message,
		MessageType: input.MessageType,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) VerifySignature(ctx context.Context, input services.VerifySignInput) (*models.MessageValidation, error) {
	response, err := Post[*models.MessageValidation](ctx, cli.httpClient, cli.baseUrl+"/v1/keys/"+input.Identifier+"/verify", resources.VerifySignBody{
		Algorithm:   input.Algorithm,
		Message:     input.Message,
		Signature:   input.Signature,
		MessageType: input.MessageType,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}
