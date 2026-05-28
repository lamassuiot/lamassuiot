package sdk

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type dmsManagerClient struct {
	httpClient *http.Client
	baseUrl    string
}

func NewHttpDMSManagerClient(client *http.Client, url string) services.DMSManagerService {
	baseURL := url
	return &dmsManagerClient{
		httpClient: client,
		baseUrl:    baseURL,
	}
}

func (cli *dmsManagerClient) GetDMSStats(ctx context.Context, input services.GetDMSStatsInput) (*models.DMSStats, error) {
	url := cli.baseUrl + "/v1/stats"
	resp, err := Get[models.DMSStats](ctx, cli.httpClient, url, input.QueryParameters, map[int][]error{})
	return &resp, err
}

func (cli *dmsManagerClient) CreateDMS(ctx context.Context, input services.CreateDMSInput) (*models.DMS, error) {
	response, err := Post[*models.DMS](ctx, cli.httpClient, cli.baseUrl+"/v1/dms", resources.CreateDMSBody{
		ID:       input.ID,
		Name:     input.Name,
		Metadata: input.Metadata,
		Settings: input.Settings,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *dmsManagerClient) UpdateDMS(ctx context.Context, input services.UpdateDMSInput) (*models.DMS, error) {
	response, err := Put[*models.DMS](ctx, cli.httpClient, cli.baseUrl+"/v1/dms/"+input.DMS.ID, input.DMS, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *dmsManagerClient) UpdateDMSMetadata(ctx context.Context, input services.UpdateDMSMetadataInput) (*models.DMS, error) {
	response, err := Put[*models.DMS](ctx, cli.httpClient, cli.baseUrl+"/v1/dms/"+input.ID+"/metadata", resources.UpdateDMSMetadataBody{
		Patches: input.Patches,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *dmsManagerClient) DeleteDMS(ctx context.Context, input services.DeleteDMSInput) error {
	err := Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/dms/"+input.ID, map[int][]error{
		404: {
			errs.ErrDMSNotFound,
		},
		400: {
			errs.ErrValidateBadRequest,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (cli *dmsManagerClient) GetDMSByID(ctx context.Context, input services.GetDMSByIDInput) (*models.DMS, error) {
	url := cli.baseUrl + "/v1/dms/" + input.ID
	resp, err := Get[models.DMS](ctx, cli.httpClient, url, nil, map[int][]error{})
	return &resp, err
}

func (cli *dmsManagerClient) GetAll(ctx context.Context, input services.GetAllInput) (string, error) {
	url := cli.baseUrl + "/v1/dms"

	return IterGet[models.DMS, *resources.GetDMSsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

// GetCMPTransactionsByDMS streams CMP transactions for the given DMS. The
// service-level domain type is storage.CMPTransaction, but the wire format
// is resources.CMPTransactionResponse — we translate per row via a wrapper
// applyFunc so the SDK consumer sees domain objects regardless of transport.
func (cli *dmsManagerClient) GetCMPTransactionsByDMS(ctx context.Context, input services.GetCMPTransactionsByDMSInput) (string, error) {
	url := cli.baseUrl + "/v1/dms/" + input.DMSID + "/cmp/transactions"
	wrap := func(item resources.CMPTransactionResponse) {
		if input.ApplyFunc != nil {
			input.ApplyFunc(storage.CMPTransaction{
				TransactionID:  item.TransactionID,
				DMSID:          item.DMSID,
				State:          storage.CMPTransactionState(item.State),
				IsReenrollment: item.IsReenrollment,
				CreatedAt:      item.CreatedAt,
				ExpiresAt:      item.ExpiresAt,
				ErrorMessage:   item.ErrorMessage,
			})
		}
	}
	return IterGet[resources.CMPTransactionResponse, *resources.GetCMPTransactionsResponse](
		ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, wrap,
		map[int][]error{
			404: {errs.ErrDMSNotFound},
		},
	)
}

// ApproveCMPTransaction approves a PENDING phased-workflow transaction, issuing
// the certificate and returning the updated transaction. The wire format is
// resources.CMPTransactionResponse; we translate it back to the domain type.
func (cli *dmsManagerClient) ApproveCMPTransaction(ctx context.Context, input services.ApproveCMPTransactionInput) (*storage.CMPTransaction, error) {
	url := cli.baseUrl + "/v1/dms/" + input.DMSID + "/cmp/transactions/" + input.TransactionID + "/approve"
	resp, err := Post[resources.CMPTransactionResponse](ctx, cli.httpClient, url, struct{}{}, map[int][]error{
		404: {errs.ErrCMPTransactionNotFound},
		409: {errs.ErrCMPTransactionNotPending},
	})
	if err != nil {
		return nil, err
	}
	return &storage.CMPTransaction{
		TransactionID:     resp.TransactionID,
		DMSID:             resp.DMSID,
		State:             storage.CMPTransactionState(resp.State),
		IsReenrollment:    resp.IsReenrollment,
		RequestType:       resp.RequestType,
		SubjectCommonName: resp.SubjectCommonName,
		CertSerialNumber:  resp.CertSerialNumber,
		WFXJobID:          resp.WFXJobID,
		CreatedAt:         resp.CreatedAt,
		ExpiresAt:         resp.ExpiresAt,
		ErrorMessage:      resp.ErrorMessage,
	}, nil
}

// RejectCMPTransaction denies a PENDING phased-workflow transaction. The row
// transitions to ISSUE_FAILED carrying the reason, which pollReq surfaces to
// the EE as an error PKIMessage. Same wire shape as ApproveCMPTransaction.
func (cli *dmsManagerClient) RejectCMPTransaction(ctx context.Context, input services.RejectCMPTransactionInput) (*storage.CMPTransaction, error) {
	url := cli.baseUrl + "/v1/dms/" + input.DMSID + "/cmp/transactions/" + input.TransactionID + "/reject"
	body := struct {
		Reason string `json:"reason,omitempty"`
	}{Reason: input.Reason}
	resp, err := Post[resources.CMPTransactionResponse](ctx, cli.httpClient, url, body, map[int][]error{
		404: {errs.ErrCMPTransactionNotFound},
		409: {errs.ErrCMPTransactionNotPending},
	})
	if err != nil {
		return nil, err
	}
	return &storage.CMPTransaction{
		TransactionID:     resp.TransactionID,
		DMSID:             resp.DMSID,
		State:             storage.CMPTransactionState(resp.State),
		IsReenrollment:    resp.IsReenrollment,
		RequestType:       resp.RequestType,
		SubjectCommonName: resp.SubjectCommonName,
		CertSerialNumber:  resp.CertSerialNumber,
		WFXJobID:          resp.WFXJobID,
		CreatedAt:         resp.CreatedAt,
		ExpiresAt:         resp.ExpiresAt,
		ErrorMessage:      resp.ErrorMessage,
	}, nil
}

func (cli *dmsManagerClient) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return nil, nil, fmt.Errorf("not supported, use the estCli instead")
}

func (cli *dmsManagerClient) LWCEnroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the cmp client instead")
}

func (cli *dmsManagerClient) LWCReenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the cmp client instead")
}

func (cli *dmsManagerClient) LWCCACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("not supported, use the cmp client instead")
}

func (cli *dmsManagerClient) LWCRevokeCertificate(ctx context.Context, input services.RevokeCertificateInput) error {
	return fmt.Errorf("not supported, use the cmp client instead")
}

func (cli *dmsManagerClient) LWCGetRootCACertUpdate(ctx context.Context, input services.GetRootCACertUpdateInput) (*services.RootCACertUpdateOutput, error) {
	return nil, fmt.Errorf("not supported, use the cmp client instead")
}

func (cli *dmsManagerClient) LWCGetCertReqTemplate(ctx context.Context, input services.GetCertReqTemplateInput) (*services.CertReqTemplateOutput, error) {
	return nil, fmt.Errorf("not supported, use the cmp client instead")
}

func (cli *dmsManagerClient) LWCGetCRL(ctx context.Context, input services.GetCMPCRLInput) (*x509.RevocationList, error) {
	return nil, fmt.Errorf("not supported, use the cmp client instead")
}

func (cli *dmsManagerClient) LWCGetEnrollmentOptions(ctx context.Context, aps string) (*services.LWCEnrollmentOptions, error) {
	return nil, fmt.Errorf("not supported, use the cmp client instead")
}

func (cli *dmsManagerClient) BindIdentityToDevice(ctx context.Context, input services.BindIdentityToDeviceInput) (*models.BindIdentityToDeviceOutput, error) {
	response, err := Post[*models.BindIdentityToDeviceOutput](ctx, cli.httpClient, cli.baseUrl+"/v1/dms/bind-identity", resources.BindIdentityToDeviceBody{
		BindMode:                input.BindMode,
		DeviceID:                input.DeviceID,
		CertificateSerialNumber: input.CertificateSerialNumber,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}
