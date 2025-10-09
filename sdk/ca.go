package sdk

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
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

func (cli *httpCAClient) GetCARequests(ctx context.Context, input services.GetItemsInput[models.CACertificateRequest]) (string, error) {
	url := cli.baseUrl + "/v1/cas/requests"
	return IterGet[models.CACertificateRequest, *resources.GetItemsResponse[models.CACertificateRequest]](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	engine, err := Get[[]*models.CryptoEngineProvider](ctx, cli.httpClient, cli.baseUrl+"/v1/engines", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return engine, nil
}

func (cli *httpCAClient) GetStats(ctx context.Context) (*models.CAStats, error) {
	stats, err := Get[*models.CAStats](ctx, cli.httpClient, cli.baseUrl+"/v1/stats", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return stats, nil
}
func (cli *httpCAClient) GetStatsByCAID(ctx context.Context, input services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	stats, err := Get[map[models.CertificateStatus]int](ctx, cli.httpClient, cli.baseUrl+"/v1/stats/"+input.CAID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (cli *httpCAClient) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	url := cli.baseUrl + "/v1/cas"
	return IterGet[models.CACertificate, *resources.GetCAsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	response, err := Get[models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpCAClient) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	url := cli.baseUrl + "/v1/cas/cn/" + input.CommonName
	return IterGet[models.CACertificate, *resources.GetCAsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) CreateCA(ctx context.Context, input services.CreateCAInput) (*models.CACertificate, error) {
	response, err := Post[*models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas", resources.CreateCABody{
		ID:           input.ID,
		Subject:      input.Subject,
		KeyMetadata:  input.KeyMetadata,
		ProfileID:    input.ProfileID,
		CAExpiration: input.CAExpiration,
		EngineID:     input.EngineID,
		ParentID:     input.ParentID,
		Metadata:     input.Metadata,
	}, map[int][]error{
		400: {
			errs.ErrCAIncompatibleValidity,
			errs.ErrCAIssuanceExpiration,
		},
		409: {
			errs.ErrCAAlreadyExists,
		},
		500: {
			errs.ErrCAIncompatibleValidity,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

// TODO --> Add Implementation
func (cli *httpCAClient) CreateHybridCA(ctx context.Context, input services.CreateHybridCAInput) (*models.CACertificate, error) {
	response, err := Post[*models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/pq", resources.CreateHybridCABody{
		ID:           input.CreateCAInput.ID,
		Subject:      input.CreateCAInput.Subject,
		OuterKeyMetadata:  input.CreateCAInput.KeyMetadata,
		InnerKeyMetadata:  input.InnerKeyMetadata,
		ProfileID:    input.CreateCAInput.ProfileID,
		CAExpiration: input.CreateCAInput.CAExpiration,
		EngineID:     input.CreateCAInput.EngineID,
		ParentID:     input.CreateCAInput.ParentID,
		Metadata:     input.CreateCAInput.Metadata,
		HybridCertificateType: input.HybridCertificateType,
	}, map[int][]error{
		400: {
			errs.ErrCAIncompatibleValidity,
			errs.ErrCAIssuanceExpiration,
		},
		409: {
			errs.ErrCAAlreadyExists,
		},
		500: {
			errs.ErrCAIncompatibleValidity,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) RequestCACSR(ctx context.Context, input services.RequestCAInput) (*models.CACertificateRequest, error) {
	response, err := Post[*models.CACertificateRequest](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/request", resources.CreateCABody{
		ID:          input.ID,
		Subject:     input.Subject,
		KeyMetadata: input.KeyMetadata,
		EngineID:    input.EngineID,
		Metadata:    input.Metadata,
	}, map[int][]error{
		400: {
			errs.ErrCAIncompatibleValidity,
			errs.ErrCAIssuanceExpiration,
		},
		409: {
			errs.ErrCAAlreadyExists,
		},
		500: {
			errs.ErrCAIncompatibleValidity,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) ImportCA(ctx context.Context, input services.ImportCAInput) (*models.CACertificate, error) {
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

	response, err := Post[*models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/import", resources.ImportCABody{
		ID:            input.ID,
		CAType:        models.CertificateType(input.CAType),
		ProfileID:     input.ProfileID,
		CACertificate: input.CACertificate,
		CAChain:       input.CAChain,
		CAPrivateKey:  privKey,
		EngineID:      input.EngineID,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) SignCertificate(ctx context.Context, input services.SignCertificateInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/certificates/sign", resources.SignCertificateBody{
		CertRequest: input.CertRequest,
		Profile:     input.IssuanceProfile,
		ProfileID:   input.IssuanceProfileID,
	}, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) CreateCertificate(ctx context.Context, input services.CreateCertificateInput) (*models.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (cli *httpCAClient) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (*models.Certificate, error) {
	response, err := Post[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/certificates/import", resources.ImportCertificateBody{
		Metadata:    input.Metadata,
		Certificate: input.Certificate,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (*models.CACertificate, error) {
	response, err := Post[*models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/status", resources.UpdateCertificateStatusBody{
		NewStatus:        input.Status,
		RevocationReason: input.RevocationReason,
	}, map[int][]error{
		400: {
			errs.ErrCertificateStatusTransitionNotAllowed,
		},
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (cli *httpCAClient) UpdateCAProfile(ctx context.Context, input services.UpdateCAProfileInput) (*models.CACertificate, error) {
	response, err := Post[*models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/profile", resources.UpdateCAProfileBody{
		ProfileID: input.ProfileID,
	}, map[int][]error{
		400: {
			errs.ErrCertificateStatusTransitionNotAllowed,
		},
		404: {
			errs.ErrCANotFound,
		},
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (cli *httpCAClient) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (*models.CACertificate, error) {
	response, err := Put[*models.CACertificate](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/metadata", resources.UpdateCAMetadataBody{
		Patches: input.Patches,
	}, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) DeleteCA(ctx context.Context, input services.DeleteCAInput) error {
	err := Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
		400: {
			errs.ErrCAStatus,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (cli *httpCAClient) SignatureSign(ctx context.Context, input services.SignatureSignInput) ([]byte, error) {
	response, err := Post[*resources.SignResponse](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/signature/sign", resources.SignatureSignBody{
		Message:          base64.StdEncoding.EncodeToString(input.Message),
		MessageType:      input.MessageType,
		SigningAlgorithm: input.SigningAlgorithm,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(response.SignedData)
}

func (cli *httpCAClient) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (bool, error) {
	response, err := Post[*resources.VerifyResponse](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/"+input.CAID+"/signature/verify", resources.SignatureVerifyBody{
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

func (cli *httpCAClient) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	response, err := Get[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber, nil, map[int][]error{
		404: {
			errs.ErrCertificateNotFound,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	url := cli.baseUrl + "/v1/certificates"
	return IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	url := cli.baseUrl + "/v1/cas/" + input.CAID + "/certificates"
	return IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
	})
}

func (cli *httpCAClient) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	url := fmt.Sprintf("%s/v1/certificates/expiration?expires_after=%s&expires_before=%s", cli.baseUrl, input.ExpiresAfter.UTC().Format("2006-01-02T15:04:05Z07:00"), input.ExpiresBefore.UTC().Format("2006-01-02T15:04:05Z07:00"))
	return IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	url := fmt.Sprintf("%s/v1/cas/%s/certificates/status/%s", cli.baseUrl, input.CAID, input.Status)

	return IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	url := fmt.Sprintf("%s/v1/certificates/status/%s", cli.baseUrl, input.Status)

	return IterGet[models.Certificate, *resources.GetCertsResponse](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (*models.Certificate, error) {
	response, err := Put[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber+"/status", resources.UpdateCertificateStatusBody{
		NewStatus:        input.NewStatus,
		RevocationReason: input.RevocationReason,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (cli *httpCAClient) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (*models.Certificate, error) {
	response, err := Put[*models.Certificate](ctx, cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber+"/metadata", resources.UpdateCertificateMetadataBody{
		Patches: input.Patches,
	}, map[int][]error{
		404: {
			errs.ErrCertificateNotFound,
		},

		400: {
			errs.ErrValidateBadRequest,
		},
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (cli *httpCAClient) DeleteCertificate(ctx context.Context, input services.DeleteCertificateInput) error {
	err := Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/certificates/"+input.SerialNumber, map[int][]error{
		404: {
			errs.ErrCertificateNotFound,
		},
		400: {
			errs.ErrValidateBadRequest,
			errs.ErrCertificateIssuerCAExists,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (cli *httpCAClient) GetCARequestByID(ctx context.Context, input services.GetByIDInput) (*models.CACertificateRequest, error) {
	response, err := Get[models.CACertificateRequest](ctx, cli.httpClient, cli.baseUrl+"/v1/cas/requests/"+input.ID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpCAClient) DeleteCARequestByID(ctx context.Context, input services.GetByIDInput) error {
	err := Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/cas/requests/"+input.ID, map[int][]error{})
	if err != nil {
		return err
	}

	return nil
}

func (cli *httpCAClient) GetIssuanceProfiles(ctx context.Context, input services.GetIssuanceProfilesInput) (string, error) {
	url := cli.baseUrl + "/v1/profiles"
	return IterGet[models.IssuanceProfile, resources.IterableList[models.IssuanceProfile]](ctx, cli.httpClient, url, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetIssuanceProfileByID(ctx context.Context, input services.GetIssuanceProfileByIDInput) (*models.IssuanceProfile, error) {
	response, err := Get[models.IssuanceProfile](ctx, cli.httpClient, cli.baseUrl+"/v1/profiles/"+input.ProfileID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpCAClient) CreateIssuanceProfile(ctx context.Context, input services.CreateIssuanceProfileInput) (*models.IssuanceProfile, error) {
	response, err := Post[*models.IssuanceProfile](ctx, cli.httpClient, cli.baseUrl+"/v1/profiles", resources.CreateUpdateIssuanceProfileBody{
		Name:                   input.Profile.Name,
		Description:            input.Profile.Description,
		Validity:               input.Profile.Validity,
		SignAsCA:               input.Profile.SignAsCA,
		HonorKeyUsage:          input.Profile.HonorKeyUsage,
		KeyUsage:               input.Profile.KeyUsage,
		HonorExtendedKeyUsages: input.Profile.HonorExtendedKeyUsages,
		ExtendedKeyUsages:      input.Profile.ExtendedKeyUsages,
		HonorSubject:           input.Profile.HonorSubject,
		Subject:                input.Profile.Subject,
		HonorExtensions:        input.Profile.HonorExtensions,
		CryptoEnforcement: resources.CreateIssuanceProfileCryptoEnforcementBody{
			Enabled:              input.Profile.CryptoEnforcement.Enabled,
			AllowRSAKeys:         input.Profile.CryptoEnforcement.AllowRSAKeys,
			AllowECDSAKeys:       input.Profile.CryptoEnforcement.AllowECDSAKeys,
			AllowedRSAKeySizes:   input.Profile.CryptoEnforcement.AllowedRSAKeySizes,
			AllowedECDSAKeySizes: input.Profile.CryptoEnforcement.AllowedECDSAKeySizes,
		},
	}, map[int][]error{
		400: {
			errs.ErrValidateBadRequest,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) UpdateIssuanceProfile(ctx context.Context, input services.UpdateIssuanceProfileInput) (*models.IssuanceProfile, error) {
	response, err := Put[*models.IssuanceProfile](ctx, cli.httpClient, cli.baseUrl+"/v1/profiles/"+input.Profile.ID, resources.CreateUpdateIssuanceProfileBody{
		Name:                   input.Profile.Name,
		Description:            input.Profile.Description,
		Validity:               input.Profile.Validity,
		SignAsCA:               input.Profile.SignAsCA,
		HonorKeyUsage:          input.Profile.HonorKeyUsage,
		KeyUsage:               input.Profile.KeyUsage,
		HonorExtendedKeyUsages: input.Profile.HonorExtendedKeyUsages,
		ExtendedKeyUsages:      input.Profile.ExtendedKeyUsages,
		HonorSubject:           input.Profile.HonorSubject,
		Subject:                input.Profile.Subject,
		HonorExtensions:        input.Profile.HonorExtensions,
		CryptoEnforcement: resources.CreateIssuanceProfileCryptoEnforcementBody{
			Enabled:              input.Profile.CryptoEnforcement.Enabled,
			AllowRSAKeys:         input.Profile.CryptoEnforcement.AllowRSAKeys,
			AllowECDSAKeys:       input.Profile.CryptoEnforcement.AllowECDSAKeys,
			AllowedRSAKeySizes:   input.Profile.CryptoEnforcement.AllowedRSAKeySizes,
			AllowedECDSAKeySizes: input.Profile.CryptoEnforcement.AllowedECDSAKeySizes,
		},
	}, map[int][]error{
		400: {
			errs.ErrValidateBadRequest,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) DeleteIssuanceProfile(ctx context.Context, input services.DeleteIssuanceProfileInput) error {
	err := Delete(ctx, cli.httpClient, cli.baseUrl+"/v1/profiles/"+input.ProfileID, map[int][]error{})
	if err != nil {
		return err
	}

	return nil
}
