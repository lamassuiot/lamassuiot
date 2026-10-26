package sdk

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
)

type KMSClient services.KMSService

type httpKMSClient struct {
	restClient
}

func NewHttpKMSClient(client *http.Client, url string) services.KMSService {
	baseURL := url
	return &httpKMSClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *httpKMSClient) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	engine, err := cli.get[[]*models.CryptoEngineProvider](ctx, "/v1/engines", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return engine, nil
}

func (cli *httpKMSClient) GetKeys(ctx context.Context, input services.GetKeysInput) (string, error) {
	path := "/v1/keys"
	return cli.iterGet[models.Key, *resources.GetKeysResponse](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpKMSClient) GetKey(ctx context.Context, input services.GetKeyInput) (*models.Key, error) {
	response, err := cli.get[models.Key](ctx, "/v1/keys/"+input.Identifier, nil, map[int][]error{
		404: {errs.ErrKeyNotFound},
	})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpKMSClient) GetKeysByPublicKey(ctx context.Context, input services.GetKeysByPublicKeyInput) ([]*models.Key, error) {
	if input.PublicKey == nil {
		return nil, errs.ErrValidateBadRequest
	}

	keyPem, err := helpers.PublicKeyToPEM(input.PublicKey)
	if err != nil {
		return nil, errs.ErrValidateBadRequest
	}

	return cli.post[[]*models.Key](ctx, "/v1/keys/lookup", resources.GetKeysByPublicKeyBody{
		PublicKey: base64.StdEncoding.EncodeToString([]byte(keyPem)),
		EngineID:  input.EngineID,
	}, map[int][]error{
		400: {errs.ErrValidateBadRequest},
	})
}

func (cli *httpKMSClient) GetKeyStats(ctx context.Context, input services.GetKeyStatsInput) (*models.KeyStats, error) {
	path := "/v1/stats"

	queryParams := input.QueryParameters
	response, err := cli.get[models.KeyStats](ctx, path, queryParams, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpKMSClient) CreateKey(ctx context.Context, input services.CreateKeyInput) (*models.Key, error) {
	response, err := cli.post[*models.Key](ctx, "/v1/keys", resources.CreateKeyBody{
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

	response, err := cli.post[*models.Key](ctx, "/v1/keys/import", resources.ImportKeyBody{
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
	response, err := cli.put[*models.Key](ctx, "/v1/keys/"+input.ID+"/metadata", resources.UpdateKeyMetadataBody{
		Patches: input.Patches,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) UpdateKeyAliases(ctx context.Context, input services.UpdateKeyAliasesInput) (*models.Key, error) {
	response, err := cli.put[*models.Key](ctx, "/v1/keys/"+input.ID+"/alias", resources.UpdateKeyAliasesBody{
		Patches: input.Patches,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) UpdateKeyName(ctx context.Context, input services.UpdateKeyNameInput) (*models.Key, error) {
	response, err := cli.put[*models.Key](ctx, "/v1/keys/"+input.ID+"/name", resources.UpdateKeyNameBody{
		Name: input.Name,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) UpdateKeyTags(ctx context.Context, input services.UpdateKeyTagsInput) (*models.Key, error) {
	response, err := cli.put[*models.Key](ctx, "/v1/keys/"+input.ID+"/tags", resources.UpdateKeyTagsBody{
		Tags: input.Tags,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) DeleteKeyByID(ctx context.Context, input services.GetKeyInput) error {
	err := cli.delete(ctx, "/v1/keys/"+input.Identifier, map[int][]error{})
	if err != nil {
		return err
	}

	return nil
}

func (cli *httpKMSClient) SignMessage(ctx context.Context, input services.SignMessageInput) (*models.MessageSignature, error) {
	response, err := cli.post[*models.MessageSignature](ctx, "/v1/keys/"+input.Identifier+"/sign", resources.SignMessageBody{
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
	response, err := cli.post[*models.MessageValidation](ctx, "/v1/keys/"+input.Identifier+"/verify", resources.VerifySignBody{
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
