package lamassuenroller

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	clientFilers "github.com/lamassuiot/lamassuiot/pkg/utils/client/filters"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
)

type LamassuDMSManagerClient interface {
	CreateDMS(ctx context.Context, input *api.CreateDMSInput) (*api.CreateDMSOutput, error)
	CreateDMSWithCertificateRequest(ctx context.Context, input *api.CreateDMSWithCertificateRequestInput) (*api.CreateDMSWithCertificateRequestOutput, error)
	UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (*api.UpdateDMSStatusOutput, error)
	UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (*api.UpdateDMSAuthorizedCAsOutput, error)
	GetDMSs(ctx context.Context, input *api.GetDMSsInput) (*api.GetDMSsOutput, error)
	GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (*api.GetDMSByNameOutput, error)
	IterateDMSsWithPredicate(ctx context.Context, input *api.IterateDMSsWithPredicateInput) (*api.IterateDMSsWithPredicateOutput, error)
}

type lamassuDMSManagerClientConfig struct {
	client clientUtils.BaseClient
}

func NewLamassuDMSManagerClientConfig(config clientUtils.ClientConfiguration) (LamassuDMSManagerClient, error) {
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
		KeyMetadata: api.CreateDMSKeyMetadataPayload{
			KeyType: string(input.KeyMetadata.KeyType),
			KeyBits: input.KeyMetadata.KeyBits,
		},
		Subject: api.CreateDMSSubjectPayload{
			CommonName:       input.Subject.CommonName,
			Organization:     input.Subject.Organization,
			OrganizationUnit: input.Subject.OrganizationUnit,
			Country:          input.Subject.Country,
			State:            input.Subject.State,
			Locality:         input.Subject.Locality,
		},
	}

	req, err := c.client.NewRequest("POST", "v1/", body)

	if err != nil {
		return &api.CreateDMSOutput{}, err
	}

	var output api.CreateDMSOutputSerialized
	_, err = c.client.Do2(req, &output)

	if err != nil {
		return &api.CreateDMSOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuDMSManagerClientConfig) CreateDMSWithCertificateRequest(ctx context.Context, input *api.CreateDMSWithCertificateRequestInput) (*api.CreateDMSWithCertificateRequestOutput, error) {
	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: input.CertificateRequest.Raw})
	base64CsrContent := base64.StdEncoding.EncodeToString(csrBytes)

	body := &api.CreateDMSWithCertificateRequestPayload{
		CertificateRequest: base64CsrContent,
	}

	req, err := c.client.NewRequest("POST", "v1/csr", body)

	if err != nil {
		return &api.CreateDMSWithCertificateRequestOutput{}, err
	}

	var output api.CreateDMSWithCertificateRequestOutputSerialized
	_, err = c.client.Do2(req, &output)

	if err != nil {
		return &api.CreateDMSWithCertificateRequestOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuDMSManagerClientConfig) UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (*api.UpdateDMSStatusOutput, error) {
	body := &api.UpdateDMSStatusPayload{
		Status: string(input.Status),
	}

	req, err := c.client.NewRequest("PUT", "v1/"+input.Name+"/status", body)

	if err != nil {
		return &api.UpdateDMSStatusOutput{}, err
	}

	var output api.UpdateDMSStatusOutputSerialized
	_, err = c.client.Do2(req, &output)

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

	req, err := c.client.NewRequest("PUT", "v1/"+input.Name+"/auth", body)

	if err != nil {
		return &api.UpdateDMSAuthorizedCAsOutput{}, err
	}

	var output api.UpdateDMSAuthorizedCAsOutputSerialized
	_, err = c.client.Do2(req, &output)

	if err != nil {
		return &api.UpdateDMSAuthorizedCAsOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuDMSManagerClientConfig) GetDMSs(ctx context.Context, input *api.GetDMSsInput) (*api.GetDMSsOutput, error) {
	req, err := c.client.NewRequest("GET", "v1/", nil)

	newParams := clientFilers.GenerateHttpQueryParams(input.QueryParameters)
	req.URL.RawQuery = newParams

	if err != nil {
		return &api.GetDMSsOutput{}, err
	}

	var output api.GetDMSsOutputSerialized
	_, err = c.client.Do2(req, &output)

	if err != nil {
		return &api.GetDMSsOutput{}, err
	}

	deserializedOutput := output.Deserialize()
	return &deserializedOutput, nil
}

func (c *lamassuDMSManagerClientConfig) GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (*api.GetDMSByNameOutput, error) {
	req, err := c.client.NewRequest("GET", "v1/"+input.Name, nil)

	if err != nil {
		return &api.GetDMSByNameOutput{}, err
	}

	var output api.GetDMSByNameOutputSerialized
	_, err = c.client.Do2(req, &output)

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
