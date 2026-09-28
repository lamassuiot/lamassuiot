package sdk

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
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

func (cli *httpKMSClient) endpoint(ctx context.Context, path string) (string, error) {
	return tenantAwareEndpoint(ctx, cli.baseUrl, path)
}

func (cli *httpKMSClient) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	endpoint, err := cli.endpoint(ctx, "/engines")
	if err != nil {
		return nil, err
	}
	engine, err := Get[[]*models.CryptoEngineProvider](ctx, cli.httpClient, endpoint, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return engine, nil
}

func (cli *httpKMSClient) GetKeys(ctx context.Context, input services.GetKeysInput) (string, error) {
	endpoint, err := cli.endpoint(ctx, "/keys")
	if err != nil {
		return "", err
	}
	return IterGet[models.Key, *resources.GetKeysResponse](ctx, cli.httpClient, endpoint, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpKMSClient) GetKey(ctx context.Context, input services.GetKeyInput) (*models.Key, error) {
	endpoint, err := cli.endpoint(ctx, "/keys/"+input.Identifier)
	if err != nil {
		return nil, err
	}
	response, err := Get[models.Key](ctx, cli.httpClient, endpoint, nil, map[int][]error{
		404: {errs.ErrKeyNotFound},
	})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpKMSClient) GetKeyStats(ctx context.Context, input services.GetKeyStatsInput) (*models.KeyStats, error) {
	endpoint, err := cli.endpoint(ctx, "/stats")
	if err != nil {
		return nil, err
	}

	queryParams := input.QueryParameters
	response, err := Get[models.KeyStats](ctx, cli.httpClient, endpoint, queryParams, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpKMSClient) CreateKey(ctx context.Context, input services.CreateKeyInput) (*models.Key, error) {
	endpoint, err := cli.endpoint(ctx, "/keys")
	if err != nil {
		return nil, err
	}
	response, err := Post[*models.Key](ctx, cli.httpClient, endpoint, resources.CreateKeyBody{
		Algorithm: input.Algorithm,
		Size:      input.Size,
		EngineID:  input.EngineID,
		Name:      input.Name,
		Tags:      input.Tags,
		Metadata:  input.Metadata,
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

	endpoint, err := cli.endpoint(ctx, "/keys/import")
	if err != nil {
		return nil, err
	}
	response, err := Post[*models.Key](ctx, cli.httpClient, endpoint, resources.ImportKeyBody{
		PrivateKey: keyB64,
		EngineID:   input.EngineID,
		Name:       input.Name,
		Tags:       input.Tags,
		Metadata:   input.Metadata,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) UpdateKeyMetadata(ctx context.Context, input services.UpdateKeyMetadataInput) (*models.Key, error) {
	endpoint, err := cli.endpoint(ctx, "/keys/"+input.ID+"/metadata")
	if err != nil {
		return nil, err
	}
	response, err := Put[*models.Key](ctx, cli.httpClient, endpoint, resources.UpdateKeyMetadataBody{
		Patches: input.Patches,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) UpdateKeyAliases(ctx context.Context, input services.UpdateKeyAliasesInput) (*models.Key, error) {
	endpoint, err := cli.endpoint(ctx, "/keys/"+input.ID+"/aliases")
	if err != nil {
		return nil, err
	}
	response, err := Put[*models.Key](ctx, cli.httpClient, endpoint, resources.UpdateKeyAliasesBody{
		Patches: input.Patches,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) UpdateKeyName(ctx context.Context, input services.UpdateKeyNameInput) (*models.Key, error) {
	endpoint, err := cli.endpoint(ctx, "/keys/"+input.ID+"/name")
	if err != nil {
		return nil, err
	}
	response, err := Put[*models.Key](ctx, cli.httpClient, endpoint, resources.UpdateKeyNameBody{
		Name: input.Name,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) UpdateKeyTags(ctx context.Context, input services.UpdateKeyTagsInput) (*models.Key, error) {
	endpoint, err := cli.endpoint(ctx, "/keys/"+input.ID+"/tags")
	if err != nil {
		return nil, err
	}
	response, err := Put[*models.Key](ctx, cli.httpClient, endpoint, resources.UpdateKeyTagsBody{
		Tags: input.Tags,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) DeleteKeyByID(ctx context.Context, input services.GetKeyInput) error {
	endpoint, err := cli.endpoint(ctx, "/keys/"+input.Identifier)
	if err != nil {
		return err
	}
	err = Delete(ctx, cli.httpClient, endpoint, map[int][]error{})
	if err != nil {
		return err
	}

	return nil
}

func (cli *httpKMSClient) SignMessage(ctx context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	endpoint, err := cli.endpoint(ctx, "/keys/"+input.Identifier+"/sign")
	if err != nil {
		return nil, err
	}
	response, err := Post[*models.MessageSignature](ctx, cli.httpClient, endpoint, resources.SignMessageBody{
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
	endpoint, err := cli.endpoint(ctx, "/keys/"+input.Identifier+"/verify")
	if err != nil {
		return nil, err
	}
	response, err := Post[*models.MessageValidation](ctx, cli.httpClient, endpoint, resources.VerifySignBody{
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
