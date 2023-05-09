package lamassuenroller

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io/ioutil"

	"github.com/fullsailor/pkcs7"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	clientFilers "github.com/lamassuiot/lamassuiot/pkg/utils/client/filters"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
)

type LamassuDMSManagerClient interface {
	CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error)
	CreateDMS(ctx context.Context, input *api.CreateDMSInput) (*api.CreateDMSOutput, error)
	UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (*api.UpdateDMSStatusOutput, error)
	UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (*api.UpdateDMSAuthorizedCAsOutput, error)
	GetDMSs(ctx context.Context, input *api.GetDMSsInput) (*api.GetDMSsOutput, error)
	GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (*api.GetDMSByNameOutput, error)
	IterateDMSsWithPredicate(ctx context.Context, input *api.IterateDMSsWithPredicateInput) (*api.IterateDMSsWithPredicateOutput, error)
}

type lamassuDMSManagerClientConfig struct {
	client clientUtils.BaseClient
}

func NewLamassuDMSManagerClientConfig(config clientUtils.BaseClientConfigurationuration) (LamassuDMSManagerClient, error) {
	baseClient, err := clientUtils.NewBaseClient(config)
	if err != nil {
		return nil, err
	}

	return &lamassuDMSManagerClientConfig{
		client: baseClient,
	}, nil
}

func (c *lamassuDMSManagerClientConfig) CreateDMS(ctx context.Context, input *api.CreateDMSInput) (*api.CreateDMSOutput, error) {
	body := &api.CreateDMSPayload{
		CloudDMS:             input.CloudDMS,
		Name:                 input.Name,
		IdentityProfile:      input.IdentityProfile.Serialize(),
		RemoteAccessIdentity: input.RemoteAccessIdentity.Serialize(),
	}

	req, err := c.client.NewRequest(ctx, "POST", "v1/", body)

	if err != nil {
		return &api.CreateDMSOutput{}, err
	}

	var output api.CreateDMSOutputSerialized
	_, err = c.client.Do(req, &output)

	if err != nil {
		return &api.CreateDMSOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuDMSManagerClientConfig) UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (*api.UpdateDMSStatusOutput, error) {
	body := &api.UpdateDMSStatusPayload{
		Status: string(input.Status),
	}

	req, err := c.client.NewRequest(ctx, "PUT", "v1/"+input.Name+"/status", body)

	if err != nil {
		return &api.UpdateDMSStatusOutput{}, err
	}

	var output api.UpdateDMSStatusOutputSerialized
	_, err = c.client.Do(req, &output)

	if err != nil {
		return &api.UpdateDMSStatusOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuDMSManagerClientConfig) UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (*api.UpdateDMSAuthorizedCAsOutput, error) {
	body := &api.UpdateDMSAuthorizedCAsPayload{
		AuthorizedCAs: input.AuthorizedCAs,
	}

	req, err := c.client.NewRequest(ctx, "PUT", "v1/"+input.Name+"/auth", body)

	if err != nil {
		return &api.UpdateDMSAuthorizedCAsOutput{}, err
	}

	var output api.UpdateDMSAuthorizedCAsOutputSerialized
	_, err = c.client.Do(req, &output)

	if err != nil {
		return &api.UpdateDMSAuthorizedCAsOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuDMSManagerClientConfig) GetDMSs(ctx context.Context, input *api.GetDMSsInput) (*api.GetDMSsOutput, error) {
	req, err := c.client.NewRequest(ctx, "GET", "v1/", nil)

	newParams := clientFilers.GenerateHttpQueryParams(input.QueryParameters)
	req.URL.RawQuery = newParams

	if err != nil {
		return &api.GetDMSsOutput{}, err
	}

	var output api.GetDMSsOutputSerialized
	_, err = c.client.Do(req, &output)

	if err != nil {
		return &api.GetDMSsOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuDMSManagerClientConfig) GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (*api.GetDMSByNameOutput, error) {
	req, err := c.client.NewRequest(ctx, "GET", "v1/"+input.Name, nil)

	if err != nil {
		return &api.GetDMSByNameOutput{}, err
	}

	var output api.GetDMSByNameOutputSerialized
	_, err = c.client.Do(req, &output)
	if err != nil {
		return &api.GetDMSByNameOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuDMSManagerClientConfig) IterateDMSsWithPredicate(ctx context.Context, input *api.IterateDMSsWithPredicateInput) (*api.IterateDMSsWithPredicateOutput, error) {
	limit := 100
	i := 0

	var dmss []api.DeviceManufacturingService = make([]api.DeviceManufacturingService, 0)

	for {
		getCAsOutput, err := c.GetDMSs(ctx, &api.GetDMSsInput{
			QueryParameters: common.QueryParameters{
				Pagination: common.PaginationOptions{
					Limit:  i,
					Offset: i * limit,
				},
			},
		})
		if err != nil {
			return &api.IterateDMSsWithPredicateOutput{}, errors.New("could not get dms list")
		}

		if len(getCAsOutput.DMSs) == 0 {
			break
		}
		dmss = append(dmss, getCAsOutput.DMSs...)
		i++
	}

	for _, dms := range dmss {
		input.PredicateFunc(&dms)
	}

	return &api.IterateDMSsWithPredicateOutput{}, nil
}

func (c *lamassuDMSManagerClientConfig) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	req, err := c.client.NewRequest(ctx, "GET", "/.well-known/est/"+aps+"/cacerts", nil)

	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do2(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	dec := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
	n, err := base64.StdEncoding.Decode(dec, body)
	if err != nil {
		return nil, err
	}
	decoded := dec[:n]
	p7, err := pkcs7.Parse(decoded)
	if err != nil {
		return nil, err
	}
	return p7.Certificates, nil
}
