package sdk

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
)

type CAClient services.CAService

type httpCAClient struct {
	restClient
	kmsClient services.KMSService
}

// NewHttpCAClient optionally accepts the KMS client used by GetCertificateKey.
func NewHttpCAClient(client *http.Client, url string, kmsClient ...services.KMSService) services.CAService {
	var kms services.KMSService
	if len(kmsClient) > 0 {
		kms = kmsClient[0]
	}
	return &httpCAClient{
		httpClient: client,
		baseUrl:    url,
		kmsClient:  kms,
	}
}

// GetCertificateKey resolves the key locally using the injected KMS client's
// existing GetKey and GetKeys HTTP endpoints.
func (cli *httpCAClient) GetCertificateKey(ctx context.Context, input services.GetCertificateKeyInput) (*models.Key, error) {
	if cli.kmsClient == nil {
		return nil, fmt.Errorf("KMS client is required to resolve certificate keys")
	}
	return services.ResolveCertificateKey(ctx, input, cli.kmsClient)
}

func (cli *httpCAClient) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	engine, err := cli.get[[]*models.CryptoEngineProvider](ctx, "/v1/engines", nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return engine, nil
}

func (cli *httpCAClient) GetStats(ctx context.Context, input services.GetStatsInput) (*models.CAStats, error) {
	r, err := http.NewRequestWithContext(ctx, "GET", cli.baseUrl+"/v1/stats", nil)
	if err != nil {
		return nil, err
	}

	// Encode both CA and Certificate query parameters with their respective prefixes
	query := r.URL.Query()
	query = encodeQueryParamsWithPrefix(query, input.CAQueryParameters, "ca_filter")
	query = encodeQueryParamsWithPrefix(query, input.CertificateQueryParameters, "cert_filter")
	r.URL.RawQuery = query.Encode()

	r.Header.Add("Content-Type", "application/json")
	res, err := cli.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, nonOKResponseToError(res.StatusCode, body, map[int][]error{})
	}

	stats, err := ParseJSON[*models.CAStats](body)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (cli *httpCAClient) GetStatsByCAID(ctx context.Context, input services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	r, err := http.NewRequestWithContext(ctx, "GET", cli.baseUrl+"/v1/stats/"+input.CAID, nil)
	if err != nil {
		return nil, err
	}

	// Encode certificate query parameters with cert_filter prefix
	query := r.URL.Query()
	query = encodeQueryParamsWithPrefix(query, input.CertificateQueryParameters, "cert_filter")
	r.URL.RawQuery = query.Encode()

	r.Header.Add("Content-Type", "application/json")
	res, err := cli.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, nonOKResponseToError(res.StatusCode, body, map[int][]error{})
	}

	stats, err := ParseJSON[map[models.CertificateStatus]int](body)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (cli *httpCAClient) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {

	path := "/v1/cas"
	return cli.iterGet[models.CACertificate, *resources.GetCAsResponse](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	response, err := cli.get[models.CACertificate](ctx, "/v1/cas/"+input.CAID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpCAClient) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	path := "/v1/cas/cn/" + input.CommonName
	return cli.iterGet[models.CACertificate, *resources.GetCAsResponse](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) CreateCA(ctx context.Context, input services.CreateCAInput) (*models.CACertificate, error) {
	response, err := cli.post[*models.CACertificate](ctx, "/v1/cas", resources.CreateCABody{
		ID:                  input.ID,
		Subject:             input.Subject,
		KeyMetadata:         input.KeyMetadata,
		ProfileID:           input.ProfileID,
		CAExpiration:        input.CAExpiration,
		EngineID:            input.EngineID,
		ParentID:            input.ParentID,
		Metadata:            input.Metadata,
		CAIssuanceProfileID: input.CAIssuanceProfileID,
		CAIssuanceProfile:   input.CAIssuanceProfile,
	}, map[int][]error{
		400: {
			errs.ErrValidateBadRequest,
			errs.ErrCAType,
			errs.ErrCAIssuanceExpiration,
			errs.ErrCAIncompatibleValidity,
		},
		404: {
			errs.ErrIssuanceProfileNotFound,
		},
		409: {
			errs.ErrCAAlreadyExists,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) ImportCA(ctx context.Context, input services.ImportCAInput) (*models.CACertificate, error) {
	var privKey string
	if input.Key != nil {
		switch input.Key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			bytes, err := x509.MarshalPKCS8PrivateKey(input.Key)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal private key: %w", err)
			}

			privKey = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: bytes,
			}))

		default:
			return nil, fmt.Errorf("unsupported private key type: %T", input.Key)
		}
	}

	response, err := cli.post[*models.CACertificate](ctx, "/v1/cas/import", resources.ImportCABody{
		ID:            input.ID,
		ProfileID:     input.ProfileID,
		CACertificate: input.CACertificate,
		CAChain:       input.CAChain,
		CAPrivateKey:  privKey,
		EngineID:      input.EngineID,
	}, map[int][]error{
		400: {
			errs.ErrValidateBadRequest,
			errs.ErrCAType,
			errs.ErrCAIssuanceExpiration,
			errs.ErrCAIncompatibleValidity,
			errs.ErrCAValidCertAndPrivKey,
		},
		404: {
			errs.ErrIssuanceProfileNotFound,
		},
		409: {
			errs.ErrCAAlreadyExists,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) SignCertificate(ctx context.Context, input services.SignCertificateInput) (*models.Certificate, error) {
	response, err := cli.post[*models.Certificate](ctx, "/v1/cas/"+input.CAID+"/certificates/sign", resources.SignCertificateBody{
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
	response, err := cli.post[*models.Certificate](ctx, "/v1/certificates", resources.CreateCertificateBody{
		CAID: input.CAID,
		KeySpec: resources.CreateCertificateBodyKeySpec{
			Type:          input.KeySpec.Type,
			Bits:          input.KeySpec.Bits,
			EngineID:      input.KeySpec.EngineID,
			KeyIdentifier: input.KeySpec.KeyIdentifier,
		},
		Subject:           input.Subject,
		IssuanceProfileID: input.IssuanceProfileID,
		IssuanceProfile:   input.IssuanceProfile,
		Metadata:          input.Metadata,
	}, map[int][]error{
		400: {
			errs.ErrInvalidKeySpec,
			errs.ErrValidateBadRequest,
			errs.ErrCAStatus,
		},
		404: {
			errs.ErrCANotFound,
			errs.ErrKeyNotFound,
			errs.ErrIssuanceProfileNotFound,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (*models.Certificate, error) {
	response, err := cli.post[*models.Certificate](ctx, "/v1/certificates/import", resources.ImportCertificateBody{
		Metadata:    input.Metadata,
		Certificate: input.Certificate,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (*models.CACertificate, error) {
	response, err := cli.post[*models.CACertificate](ctx, "/v1/cas/"+input.CAID+"/status", resources.UpdateCertificateStatusBody{
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
	response, err := cli.post[*models.CACertificate](ctx, "/v1/cas/"+input.CAID+"/profile", resources.UpdateCAProfileBody{
		ProfileID: input.ProfileID,
	}, map[int][]error{
		400: {
			errs.ErrCertificateStatusTransitionNotAllowed,
		},
		404: {
			errs.ErrCANotFound,
			errs.ErrIssuanceProfileNotFound,
		},
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (cli *httpCAClient) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (*models.CACertificate, error) {
	response, err := cli.put[*models.CACertificate](ctx, "/v1/cas/"+input.CAID+"/metadata", resources.UpdateCAMetadataBody{
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

func (cli *httpCAClient) ReissueCA(ctx context.Context, input services.ReissueCAInput) (*models.CACertificate, error) {
	response, err := cli.post[*models.CACertificate](ctx, "/v1/cas/"+input.CAID+"/reissue", nil, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
		400: {
			errs.ErrCAAlreadyRevoked,
			errs.ErrCAExpired,
			errs.ErrValidateBadRequest,
		},
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (cli *httpCAClient) DeleteCA(ctx context.Context, input services.DeleteCAInput) error {
	path := "/v1/cas/" + input.CAID

	// Add cascade_delete query parameter if needed
	if input.CascadeDelete {
		path += "?cascade_delete=true"
	}

	err := cli.delete(ctx, path, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
		400: {
			errs.ErrCAStatus,
		},
		403: {
			errs.ErrCascadeDeleteNotAllowed,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (cli *httpCAClient) SignatureSign(ctx context.Context, input services.SignatureSignInput) ([]byte, error) {
	response, err := cli.post[*resources.SignResponse](ctx, "/v1/cas/"+input.CAID+"/signature/sign", resources.SignatureSignBody{
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
	response, err := cli.post[*resources.VerifyResponse](ctx, "/v1/cas/"+input.CAID+"/signature/verify", resources.SignatureVerifyBody{
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
	response, err := cli.get[*models.Certificate](ctx, "/v1/certificates/"+input.SerialNumber, nil, map[int][]error{
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
	path := "/v1/certificates"
	return cli.iterGet[models.Certificate, *resources.GetCertsResponse](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	path := "/v1/cas/" + input.CAID + "/certificates"
	return cli.iterGet[models.Certificate, *resources.GetCertsResponse](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{
		404: {
			errs.ErrCANotFound,
		},
	})
}

func (cli *httpCAClient) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	path := fmt.Sprintf("/v1/certificates/expiration?expires_after=%s&expires_before=%s", input.ExpiresAfter.UTC().Format("2006-01-02T15:04:05Z07:00"), input.ExpiresBefore.UTC().Format("2006-01-02T15:04:05Z07:00"))
	return cli.iterGet[models.Certificate, *resources.GetCertsResponse](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	path := fmt.Sprintf("/v1/cas/%s/certificates/status/%s", input.CAID, input.Status)

	return cli.iterGet[models.Certificate, *resources.GetCertsResponse](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	path := fmt.Sprintf("/v1/certificates/status/%s", input.Status)

	return cli.iterGet[models.Certificate, *resources.GetCertsResponse](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (*models.Certificate, error) {
	response, err := cli.put[*models.Certificate](ctx, "/v1/certificates/"+input.SerialNumber+"/status", resources.UpdateCertificateStatusBody{
		NewStatus:        input.NewStatus,
		RevocationReason: input.RevocationReason,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (cli *httpCAClient) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (*models.Certificate, error) {
	response, err := cli.put[*models.Certificate](ctx, "/v1/certificates/"+input.SerialNumber+"/metadata", resources.UpdateCertificateMetadataBody{
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
	err := cli.delete(ctx, "/v1/certificates/"+input.SerialNumber, map[int][]error{
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

func (cli *httpCAClient) GetIssuanceProfiles(ctx context.Context, input services.GetIssuanceProfilesInput) (string, error) {
	path := "/v1/profiles"
	return cli.iterGet[models.IssuanceProfile, resources.IterableList[models.IssuanceProfile]](ctx, path, input.ExhaustiveRun, input.QueryParameters, input.ApplyFunc, map[int][]error{})
}

func (cli *httpCAClient) GetIssuanceProfileByID(ctx context.Context, input services.GetIssuanceProfileByIDInput) (*models.IssuanceProfile, error) {
	response, err := cli.get[models.IssuanceProfile](ctx, "/v1/profiles/"+input.ProfileID, nil, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (cli *httpCAClient) CreateIssuanceProfile(ctx context.Context, input services.CreateIssuanceProfileInput) (*models.IssuanceProfile, error) {
	response, err := cli.post[*models.IssuanceProfile](ctx, "/v1/profiles", resources.CreateUpdateIssuanceProfileBody{
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
	response, err := cli.put[*models.IssuanceProfile](ctx, "/v1/profiles/"+input.Profile.ID, resources.CreateUpdateIssuanceProfileBody{
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
	err := cli.delete(ctx, "/v1/profiles/"+input.ProfileID, map[int][]error{})
	if err != nil {
		return err
	}

	return nil
}

func (cli *httpCAClient) ImportKey(ctx context.Context, input services.ImportKeyInput) (*models.Key, error) {
	keyPem, err := helpers.PrivateKeyToPEM(input.PrivateKey)
	if err != nil {
		return nil, err
	}

	keyB64 := base64.StdEncoding.EncodeToString([]byte(keyPem))

	response, err := cli.post[*models.Key](ctx, "/v1/kms/keys/import", resources.ImportKeyBody{
		PrivateKey: keyB64,
		EngineID:   input.EngineID,
		Name:       input.Name,
	}, map[int][]error{})
	if err != nil {
		return nil, err
	}

	return response, nil
}
