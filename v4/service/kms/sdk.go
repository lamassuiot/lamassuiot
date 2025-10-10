package kms

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
)

type httpKMSClient struct {
	httpClient *http.Client
	baseUrl    string
}

func NewHttpKMSClient(client *http.Client, url string) KMSService {
	return &httpKMSClient{
		httpClient: client,
		baseUrl:    url,
	}
}

func (cli *httpKMSClient) GetKeys(ctx context.Context, input GetKeysInput) (string, error) {
	url := cli.baseUrl + "/v1/kms/keys"
	return sdk.IterGet[Key, *GetKeysResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpKMSClient) GetKeyByID(ctx context.Context, input GetKeyByIDInput) (*Key, error) {
	response, err := sdk.Get[*Key](ctx, cli.httpClient, cli.baseUrl+"/v1/kms/keys/"+input.ID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) CreateKey(ctx context.Context, input CreateKeyInput) (*Key, error) {
	response, err := sdk.Post[*Key](ctx, cli.httpClient, cli.baseUrl+"/v1/kms/keys", CreateKeyBody{
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

func (cli *httpKMSClient) ImportKey(ctx context.Context, input ImportKeyInput) (*Key, error) {
	keyPem, err := helpers.PrivateKeyToPEM(input.PrivateKey)
	if err != nil {
		return nil, err
	}

	keyB64 := base64.StdEncoding.EncodeToString([]byte(keyPem))

	response, err := sdk.Post[*Key](ctx, cli.httpClient, cli.baseUrl+"/v1/kms/keys/import", ImportKeyBody{
		PrivateKey: keyB64,
		EngineID:   input.EngineID,
		Name:       input.Name,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) DeleteKeyByID(ctx context.Context, input GetKeyByIDInput) error {
	err := sdk.Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/kms/keys/"+input.ID, map[int][]error{})
	if err != nil {
		return err
	}

	return nil
}

func (cli *httpKMSClient) SignMessage(ctx context.Context, input SignMessageInput) (*MessageSignature, error) {
	response, err := sdk.Post[*MessageSignature](ctx, cli.httpClient, cli.baseUrl+"/v1/kms/keys/"+input.KeyID+"/sign", SignMessageBody{
		Algorithm:   input.Algorithm,
		Message:     input.Message,
		MessageType: input.MessageType,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpKMSClient) VerifySignature(ctx context.Context, input VerifySignInput) (*MessageValidation, error) {
	response, err := sdk.Post[*MessageValidation](ctx, cli.httpClient, cli.baseUrl+"/v1/kms/keys/"+input.KeyID+"/verify", VerifySignBody{
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
