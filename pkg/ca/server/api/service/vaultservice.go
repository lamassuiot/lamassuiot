package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/hashicorp/go-cleanhttp"
	vaultApi "github.com/hashicorp/vault/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	caerrors "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
)

type VaultSecrets struct {
	client                *vaultApi.Client
	certificateRepository repository.Certificates
	roleID                string
	secretID              string
	pkiPath               string
	ocspUrl               string
	logger                log.Logger
}

func NewVaultService(address string, pkiPath string, roleID string, secretID string, CA string, unsealFile string, ocspUrl string, certificateRepository repository.Certificates, logger log.Logger) (*VaultSecrets, error) {
	client, err := CreateVaultSdkClient(address, CA, logger)
	if err != nil {
		return nil, errors.New("Could not create Vault API client: " + err.Error())
	}

	err = Unseal(client, unsealFile, logger)
	if err != nil {
		return nil, errors.New("Could not unseal Vault: " + err.Error())
	}

	err = Login(client, roleID, secretID)
	if err != nil {
		return nil, errors.New("Could not login into Vault: " + err.Error())
	}
	v := VaultSecrets{
		client:                client,
		pkiPath:               pkiPath,
		roleID:                roleID,
		secretID:              secretID,
		ocspUrl:               ocspUrl,
		logger:                logger,
		certificateRepository: certificateRepository,
	}
	_, err = v.GetCAByName(context.Background(), &api.GetCAByNameInput{
		CAType: api.CATypeDMSEnroller,
		CAName: "LAMASSU-DMS-MANAGER",
	})

	if err != nil {
		level.Debug(logger).Log("msg", "failed to get LAMASSU-DMS-MANAGER", "err", err)
		level.Debug(logger).Log("msg", "Generating LAMASSU-DMS-MANAGER CA", "err", err)
		v.CreateCA(context.Background(), &api.CreateCAInput{
			CAType: api.CATypeDMSEnroller,
			Subject: api.Subject{
				CommonName:   "LAMASSU-DMS-MANAGER",
				Organization: "lamassu",
			},
			KeyMetadata: api.KeyMetadata{
				KeyType: "RSA",
				KeyBits: 4096,
			},
			CADuration:       time.Hour * 24 * 365 * 5,
			IssuanceDuration: time.Hour * 24 * 365 * 3,
		})
	}
	return &v, nil
}

func NewVaultSecretsWithClient(client *vaultApi.Client, address string, pkiPath string, roleID string, secretID string, CA string, unsealFile string, ocspUrl string, certificateRepository repository.Certificates, logger log.Logger) (*VaultSecrets, error) {
	v := VaultSecrets{
		client:                client,
		pkiPath:               pkiPath,
		roleID:                roleID,
		secretID:              secretID,
		ocspUrl:               ocspUrl,
		logger:                logger,
		certificateRepository: certificateRepository,
	}

	_, err := v.GetCAByName(context.Background(), &api.GetCAByNameInput{
		CAType: api.CATypeDMSEnroller,
		CAName: "LAMASSU-DMS-MANAGER",
	})

	if err != nil {
		level.Debug(logger).Log("msg", "failed to get LAMASSU-DMS-MANAGER", "err", err)
		level.Debug(logger).Log("msg", "Generating LAMASSU-DMS-MANAGER CA", "err", err)
		v.CreateCA(context.Background(), &api.CreateCAInput{
			CAType: api.CATypeDMSEnroller,
			Subject: api.Subject{
				CommonName:   "LAMASSU-DMS-MANAGER",
				Organization: "lamassu",
			},
			KeyMetadata: api.KeyMetadata{
				KeyType: "RSA",
				KeyBits: 4096,
			},
			CADuration:       time.Hour * 24 * 365 * 5,
			IssuanceDuration: time.Hour * 24 * 365 * 3,
		})
	}
	return &v, nil
}

func CreateVaultSdkClient(vaultAddress string, vaultCaCertFilePath string, logger log.Logger) (*vaultApi.Client, error) {
	conf := vaultApi.DefaultConfig()
	httpClient := cleanhttp.DefaultPooledClient()
	httpTrasport := cleanhttp.DefaultPooledTransport()
	caPool := x509.NewCertPool()

	vaultCAFile, err := os.ReadFile(vaultCaCertFilePath)
	if err != nil {
		return nil, err
	}

	caPool.AppendCertsFromPEM(vaultCAFile)

	httpTrasport.TLSClientConfig = &tls.Config{
		RootCAs: caPool,
	}
	httpClient.Transport = httpTrasport
	conf.HttpClient = httpClient
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", vaultAddress)
	// tlsConf := &api.TLSConfig{CACert: CA}
	// conf.ConfigureTLS(tlsConf)
	return vaultApi.NewClient(conf)

}

func Unseal(client *vaultApi.Client, unsealFile string, logger log.Logger) error {
	usnealJsonFile, err := os.Open(unsealFile)
	if err != nil {
		return err
	}

	unsealFileByteValue, _ := ioutil.ReadAll(usnealJsonFile)
	var unsealKeys []interface{}

	err = json.Unmarshal(unsealFileByteValue, &unsealKeys)
	if err != nil {
		return err
	}

	providedSharesCount := 0
	sealed := true

	for sealed {
		unsealStatusProgress, err := client.Sys().Unseal(unsealKeys[providedSharesCount].(string))
		if err != nil {
			level.Debug(logger).Log("err", "Error while unsealing vault", "provided_unseal_keys", providedSharesCount)
			return err
		}
		level.Debug(logger).Log("msg", "Unseal progress shares="+strconv.Itoa(unsealStatusProgress.N)+" threshold="+strconv.Itoa(unsealStatusProgress.T)+" remaining_shares="+strconv.Itoa(unsealStatusProgress.Progress))

		providedSharesCount++
		if !unsealStatusProgress.Sealed {
			level.Debug(logger).Log("msg", "Vault is unsealed")
			sealed = false
		}
	}
	return nil
}

func Login(client *vaultApi.Client, roleID string, secretID string) error {

	loginPath := "auth/approle/login"
	options := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	resp, err := client.Logical().Write(loginPath, options)
	if err != nil {
		return err
	}
	client.SetToken(resp.Auth.ClientToken)
	return nil
}

func (v *VaultSecrets) Health() bool {
	return true
}

func (v *VaultSecrets) GetEngineProviderInfo() api.EngineProviderInfo {
	pkcs11ProviderSupportedKeyTypes := []api.SupportedKeyTypeInfo{}

	pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, api.SupportedKeyTypeInfo{
		Type:        "RSA",
		MinimumSize: 2048,
		MaximumSize: 4096,
	})

	pkcs11ProviderSupportedKeyTypes = append(pkcs11ProviderSupportedKeyTypes, api.SupportedKeyTypeInfo{
		Type:        "ECDSA",
		MinimumSize: 224,
		MaximumSize: 521,
	})

	return api.EngineProviderInfo{
		Provider:          "Hashicorp Vault",
		Manufacturer:      "Hashicorp",
		Model:             "v11",
		CryptokiVersion:   "-",
		Library:           "-",
		SupportedKeyTypes: pkcs11ProviderSupportedKeyTypes,
	}
}

func (v *VaultSecrets) Stats(ctx context.Context, input *api.GetStatsInput) (*api.GetStatsOutput, error) {
	stats := api.GetStatsOutput{
		IssuedCerts: 0,
		CAs:         0,
		ScanDate:    time.Now(),
	}

	v.IterateCAsWithPredicate(ctx, &api.IterateCAsWithPredicateInput{
		CAType: api.CATypePKI,
		PredicateFunc: func(c *api.CACertificate) {
			getCertificatesOutput, err := v.GetCertificates(ctx, &api.GetCertificatesInput{
				CAType: api.CATypePKI,
				CAName: c.CAName,
			})
			if err != nil {
				return
			}

			stats.CAs++
			stats.IssuedCerts += getCertificatesOutput.TotalCertificates
		},
	})

	return &stats, nil
}

func (v *VaultSecrets) CreateCA(ctx context.Context, input *api.CreateCAInput) (*api.CreateCAOutput, error) {
	if input.KeyMetadata.KeyType == "RSA" {
		input.KeyMetadata.KeyType = "rsa"
	} else if input.KeyMetadata.KeyType == "EC" {
		input.KeyMetadata.KeyType = "ec"
	}
	err := v.initPkiSecret(ctx, input.CAType, input.Subject.CommonName, fmt.Sprint(input.IssuanceDuration.Hours()))
	if err != nil {
		return &api.CreateCAOutput{}, err
	}
	tuneOptions := map[string]interface{}{
		"max_lease_ttl": fmt.Sprint(input.CADuration.Hours()) + "h",
	}
	_, err = v.client.Logical().Write("/sys/mounts/"+v.pkiPath+api.ToVaultPath(string(input.CAType))+input.Subject.CommonName+"/tune", tuneOptions)

	if err != nil {
		level.Debug(v.logger).Log("err", err, "msg", "Could not tune CA "+input.Subject.CommonName)
		return &api.CreateCAOutput{}, err
	}

	options := map[string]interface{}{
		"key_type":          input.KeyMetadata.KeyType,
		"key_bits":          input.KeyMetadata.KeyBits,
		"country":           input.Subject.Country,
		"province":          input.Subject.State,
		"locality":          input.Subject.Locality,
		"organization":      input.Subject.Organization,
		"organization_unit": input.Subject.OrganizationUnit,
		"common_name":       input.Subject.CommonName,
		"ttl":               fmt.Sprint(input.CADuration.Hours()) + "h",
	}
	_, err = v.client.Logical().Write(v.pkiPath+api.ToVaultPath(string(input.CAType))+input.Subject.CommonName+"/root/generate/internal", options)

	if err != nil {
		level.Debug(v.logger).Log("err", err, "msg", "Could not intialize the root CA certificate for "+input.Subject.CommonName+" CA on Vault")
		return &api.CreateCAOutput{}, err
	}
	resp, err := v.client.Logical().Read(v.pkiPath + api.ToVaultPath(string(input.CAType)) + input.Subject.CommonName + "/cert/ca")

	if err != nil {
		level.Debug(v.logger).Log("err", err, "msg", "Could not read "+input.Subject.CommonName+" certificate from Vault")
		return &api.CreateCAOutput{}, errors.New("could not read certificate from Vault")
	}
	if resp == nil {
		level.Debug(v.logger).Log("Mount path for PKI " + input.Subject.CommonName + " does not have a root CA")
		return &api.CreateCAOutput{}, errors.New("mount path for PKI does not have a root CA")
	}

	certBytes := []byte(resp.Data["certificate"].(string))
	cert, err := DecodeCert(certBytes)
	if err != nil {
		err = errors.New("cannot decode cert. Perhaps it is malphormed")
		level.Debug(v.logger).Log("err", err)
		return &api.CreateCAOutput{}, err
	}
	err = v.certificateRepository.InsertCA(ctx, input.CAType, &cert, input.IssuanceDuration)
	if err != nil {
		level.Debug(v.logger).Log("err", err)
		return &api.CreateCAOutput{}, err
	}
	cainfo := api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.Subject.CommonName,
	}
	ca, err := v.GetCAByName(ctx, &cainfo)
	keyType, keySize, keyStrength := getPublicKeyInfo(ca.Certificate.Certificate)
	ca.KeyMetadata = api.KeyStrengthMetadata{
		KeyType:     keyType,
		KeyBits:     keySize,
		KeyStrength: keyStrength,
	}
	return &api.CreateCAOutput{
		CACertificate: ca.CACertificate,
	}, nil
}

func (v *VaultSecrets) GetCAs(ctx context.Context, input *api.GetCAsInput) (*api.GetCAsOutput, error) {
	output := api.GetCAsOutput{}

	if input.QueryParameters.Pagination.Limit == 0 {
		input.QueryParameters.Pagination.Limit = 100
	}
	totalCAs, CAs, err := v.certificateRepository.SelectCAs(ctx, api.CATypePKI, input.QueryParameters)
	if err != nil {
		return &output, err
	}
	for i, ca := range CAs {
		if ca.Certificate.Certificate.NotAfter.Before(time.Now()) {
			if ca.Status != api.StatusExpired && ca.Status != api.StatusRevoked {
				updateCAOutput, err := v.UpdateCAStatus(ctx, &api.UpdateCAStatusInput{
					CAType: api.CATypePKI,
					CAName: ca.CAName,
					Status: api.StatusExpired,
				})
				if err != nil {
					level.Debug(v.logger).Log("err", err, "msg", "Could not update the status of an expired CA status: "+ca.CAName)
					continue
				}
				CAs[i] = updateCAOutput.CACertificate
			}
		}

		keyType, keySize, keyStrength := getPublicKeyInfo(ca.Certificate.Certificate)
		CAs[i].KeyMetadata = api.KeyStrengthMetadata{
			KeyType:     keyType,
			KeyBits:     keySize,
			KeyStrength: keyStrength,
		}
	}

	output = api.GetCAsOutput{
		TotalCAs: totalCAs,
		CAs:      CAs,
	}
	return &output, nil
}

func (v *VaultSecrets) GetCAByName(ctx context.Context, input *api.GetCAByNameInput) (*api.GetCAByNameOutput, error) {
	ca, err := v.certificateRepository.SelectCAByName(ctx, input.CAType, input.CAName)
	if err != nil {
		return &api.GetCAByNameOutput{}, err
	}
	if ca.Certificate.Certificate.NotAfter.Before(time.Now()) {
		if ca.Status != api.StatusExpired && ca.Status != api.StatusRevoked {
			updateCAOutput, err := v.UpdateCAStatus(ctx, &api.UpdateCAStatusInput{
				CAType: api.CATypePKI,
				CAName: ca.CAName,
				Status: api.StatusExpired,
			})
			if err != nil {
				level.Debug(v.logger).Log("err", err, "msg", "Could not update the status of an expired CA status: "+ca.CAName)
				return &api.GetCAByNameOutput{}, err
			}
			ca = updateCAOutput.CACertificate
		}
	}
	keyType, keySize, keyStrength := getPublicKeyInfo(ca.Certificate.Certificate)
	ca.KeyMetadata = api.KeyStrengthMetadata{
		KeyType:     keyType,
		KeyBits:     keySize,
		KeyStrength: keyStrength,
	}
	return &api.GetCAByNameOutput{
		CACertificate: ca,
	}, nil
}
func (v *VaultSecrets) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error) {
	switch input.Status {
	case api.StatusRevoked:
		v.RevokeCA(ctx, &api.RevokeCAInput{
			CAType: input.CAType,
			CAName: input.CAName,
		})
	default:
		v.certificateRepository.UpdateCAStatus(ctx, input.CAType, input.CAName, input.Status, "")
	}

	outputCertificate, _ := v.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})

	return &api.UpdateCAStatusOutput{
		CACertificate: outputCertificate.CACertificate,
	}, nil
}

func (v *VaultSecrets) RevokeCA(ctx context.Context, input *api.RevokeCAInput) (*api.RevokeCAOutput, error) {
	outputCAs, err := v.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})
	if outputCAs.Status == api.StatusRevoked {
		return &api.RevokeCAOutput{}, errors.New(caerrors.ErrAlreadyRevoked)
	}
	if err != nil {
		return &api.RevokeCAOutput{}, err
	}

	err = v.certificateRepository.UpdateCAStatus(ctx, input.CAType, input.CAName, api.StatusRevoked, input.RevocationReason)
	if err != nil {
		return &api.RevokeCAOutput{}, err
	}
	v.IterateCertificatesWithPredicate(ctx, &api.IterateCertificatesWithPredicateInput{
		CAType: input.CAType,
		CAName: input.CAName,
		PredicateFunc: func(c *api.Certificate) {
			_, err := v.RevokeCertificate(ctx, &api.RevokeCertificateInput{
				CAType:                  input.CAType,
				CAName:                  input.CAName,
				CertificateSerialNumber: c.SerialNumber,
				RevocationReason:        "Automatic revocation due to CA revocation",
			})
			if err != nil {
				fmt.Println(err)
			}
		},
	})
	outputCAs, _ = v.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})
	return &api.RevokeCAOutput{
		CACertificate: outputCAs.CACertificate,
	}, nil
}

func (v *VaultSecrets) IterateCAsWithPredicate(ctx context.Context, input *api.IterateCAsWithPredicateInput) (*api.IterateCAsWithPredicateOutput, error) {
	var cas []api.CACertificate
	limit := 100
	i := 0

	for {
		casOutput, err := v.GetCAs(
			ctx,
			&api.GetCAsInput{
				CAType: input.CAType,
				QueryParameters: common.QueryParameters{
					Pagination: common.PaginationOptions{
						Limit:  i,
						Offset: i * limit,
					},
				},
			},
		)
		if err != nil {
			return &api.IterateCAsWithPredicateOutput{}, err
		}

		if len(casOutput.CAs) == 0 {
			break
		}

		cas = append(cas, casOutput.CAs...)
		i++
	}

	for _, ca := range cas {
		input.PredicateFunc(&ca)
	}

	return &api.IterateCAsWithPredicateOutput{}, nil
}

func (v *VaultSecrets) SignCertificateRequest(ctx context.Context, input *api.SignCertificateRequestInput) (*api.SignCertificateRequestOutput, error) {
	caOutput, err := v.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})
	if err != nil {
		level.Debug(v.logger).Log("err", err)
		return &api.SignCertificateRequestOutput{}, err
	}

	if caOutput.Status == api.StatusExpired || caOutput.Status == api.StatusRevoked {
		return &api.SignCertificateRequestOutput{}, errors.New("CA is expired or revoked")
	}

	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: input.CertificateSigningRequest.Raw})
	options := map[string]interface{}{
		"csr":         string(csrBytes),
		"common_name": input.CommonName,
	}

	var data *vaultApi.Secret
	if input.SignVerbatim {
		data, err = v.client.Logical().Write(v.pkiPath+api.ToVaultPath(string(input.CAType))+input.CAName+"/sign-verbatim/enroller", options)
	} else {
		options["exclude_cn_from_sans"] = true
		data, err = v.client.Logical().Write(v.pkiPath+api.ToVaultPath(string(input.CAType))+input.CAName+"/sign/enroller", options)
	}
	if err != nil {
		notFoundErr := &caerrors.ResourceNotFoundError{
			ResourceType: "Sign Certificate",
			ResourceId:   input.CAName,
		}
		return &api.SignCertificateRequestOutput{}, notFoundErr
	}
	certData := data.Data["certificate"]
	certPEMBlock, _ := pem.Decode([]byte(certData.(string)))
	if certPEMBlock == nil || certPEMBlock.Type != "CERTIFICATE" {
		err = errors.New("failed to decode PEM block containing certificate")
		return &api.SignCertificateRequestOutput{}, err
	}
	caCert := data.Data["issuing_ca"]
	caCertPEMBlock, _ := pem.Decode([]byte(caCert.(string)))
	if caCertPEMBlock == nil || caCertPEMBlock.Type != "CERTIFICATE" {
		err = errors.New("failed to decode PEM block containing certificate")
		return &api.SignCertificateRequestOutput{}, err
	}
	certificate, err := x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		level.Debug(v.logger).Log("err", err)
		return &api.SignCertificateRequestOutput{}, err
	}
	err = v.certificateRepository.InsertCertificate(ctx, input.CAType, input.CAName, certificate)
	if err != nil {
		level.Debug(v.logger).Log("err", err)
		return &api.SignCertificateRequestOutput{}, err
	}
	return &api.SignCertificateRequestOutput{
		Certificate:   certificate,
		CACertificate: caOutput.Certificate.Certificate,
	}, nil
}

func (v *VaultSecrets) RevokeCertificate(ctx context.Context, input *api.RevokeCertificateInput) (*api.RevokeCertificateOutput, error) {
	options := map[string]interface{}{
		"serial_number": input.CertificateSerialNumber,
	}
	certinfo := api.GetCertificateBySerialNumberInput{
		CAType:                  input.CAType,
		CAName:                  input.CAName,
		CertificateSerialNumber: input.CertificateSerialNumber,
	}
	cert, err := v.GetCertificateBySerialNumber(ctx, &certinfo)
	if err != nil {
		return &api.RevokeCertificateOutput{}, err
	}
	if cert.Status == api.StatusRevoked {
		return &api.RevokeCertificateOutput{}, errors.New(caerrors.ErrAlreadyRevoked)
	}
	err = v.certificateRepository.UpdateCertificateStatus(ctx, input.CAType, input.CAName, input.CertificateSerialNumber, api.StatusRevoked, input.RevocationReason)
	if err != nil {
		return &api.RevokeCertificateOutput{}, err
	}

	_, err = v.client.Logical().Write(v.pkiPath+api.ToVaultPath(string(input.CAType))+input.CAName+"/revoke", options)
	if err != nil {
		level.Debug(v.logger).Log("err", err, "msg", "Could not revoke cert with serial number "+input.CertificateSerialNumber+" from CA "+input.CAName)
		err = errors.New("could not revoke cert from CA")
		return &api.RevokeCertificateOutput{}, err
	}

	outputCertificate, _ := v.GetCertificateBySerialNumber(ctx, &certinfo)
	return &api.RevokeCertificateOutput{
		Certificate: outputCertificate.Certificate,
	}, nil
}

func (v *VaultSecrets) GetCertificateBySerialNumber(ctx context.Context, input *api.GetCertificateBySerialNumberInput) (*api.GetCertificateBySerialNumberOutput, error) {
	certificate, err := v.certificateRepository.SelectCertificateBySerialNumber(ctx, input.CAType, input.CAName, input.CertificateSerialNumber)
	if err != nil {
		return &api.GetCertificateBySerialNumberOutput{}, err
	}

	if certificate.Certificate.NotAfter.Before(time.Now()) {
		if certificate.Status != api.StatusExpired && certificate.Status != api.StatusRevoked {
			updateCertificateOutput, err := v.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
				CAType:                  input.CAType,
				CAName:                  certificate.CAName,
				CertificateSerialNumber: certificate.SerialNumber,
				Status:                  api.StatusExpired,
			})
			if err != nil {
				level.Debug(v.logger).Log("err", err, "msg", "Could not update the status of an expired Certificate status: "+certificate.CAName+"-"+certificate.SerialNumber)
				return &api.GetCertificateBySerialNumberOutput{}, err
			}
			certificate = updateCertificateOutput.Certificate
		}
	}

	keyType, keySize, keyStrength := getPublicKeyInfo(certificate.Certificate)
	certificate.KeyMetadata = api.KeyStrengthMetadata{
		KeyType:     keyType,
		KeyBits:     keySize,
		KeyStrength: keyStrength,
	}

	return &api.GetCertificateBySerialNumberOutput{
		Certificate: certificate,
	}, nil
}

func (v *VaultSecrets) GetCertificates(ctx context.Context, input *api.GetCertificatesInput) (*api.GetCertificatesOutput, error) {
	output := api.GetCertificatesOutput{}

	if input.QueryParameters.Pagination.Limit == 0 {
		input.QueryParameters.Pagination.Limit = 100
	}

	_, err := v.certificateRepository.SelectCAByName(ctx, input.CAType, input.CAName)
	if err != nil {
		return &output, err
	}

	totalCertificates, certificates, err := v.certificateRepository.SelectCertificatesByCA(ctx, input.CAType, input.CAName, input.QueryParameters)
	if err != nil {
		return &output, err
	}

	for i, c := range certificates {
		if c.Certificate.NotAfter.Before(time.Now()) {
			if c.Status != api.StatusExpired && c.Status != api.StatusRevoked {
				updateCertificateOutput, err := v.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
					CAType:                  input.CAType,
					CAName:                  c.CAName,
					CertificateSerialNumber: c.SerialNumber,
					Status:                  api.StatusExpired,
				})
				if err != nil {
					level.Debug(v.logger).Log("err", err, "msg", "Could not update the status of an expired Certificate status: "+c.CAName+"-"+c.SerialNumber)
					return &api.GetCertificatesOutput{}, err
				}
				certificates[i] = updateCertificateOutput.Certificate
			}
		}

		keyType, keySize, keyStrength := getPublicKeyInfo(c.Certificate)
		certificates[i].KeyMetadata = api.KeyStrengthMetadata{
			KeyType:     keyType,
			KeyBits:     keySize,
			KeyStrength: keyStrength,
		}
	}

	output = api.GetCertificatesOutput{
		TotalCertificates: totalCertificates,
		Certificates:      certificates,
	}

	return &output, err
}

func (v *VaultSecrets) UpdateCertificateStatus(ctx context.Context, input *api.UpdateCertificateStatusInput) (*api.UpdateCertificateStatusOutput, error) {
	switch input.Status {
	case api.StatusRevoked:
		v.RevokeCertificate(ctx, &api.RevokeCertificateInput{
			CAType:                  input.CAType,
			CAName:                  input.CAName,
			CertificateSerialNumber: input.CertificateSerialNumber,
		})
	default:
		v.certificateRepository.UpdateCertificateStatus(ctx, input.CAType, input.CAName, input.CertificateSerialNumber, input.Status, "")
	}

	outputCertificate, _ := v.GetCertificateBySerialNumber(ctx, &api.GetCertificateBySerialNumberInput{
		CAType:                  input.CAType,
		CAName:                  input.CAName,
		CertificateSerialNumber: input.CertificateSerialNumber,
	})

	return &api.UpdateCertificateStatusOutput{
		Certificate: outputCertificate.Certificate,
	}, nil
}

func (v *VaultSecrets) IterateCertificatesWithPredicate(ctx context.Context, input *api.IterateCertificatesWithPredicateInput) (*api.IterateCertificatesWithPredicateOutput, error) {
	output := api.IterateCertificatesWithPredicateOutput{}

	var certificates []api.Certificate
	limit := 100
	i := 0

	for {
		certsOutput, err := v.GetCertificates(ctx, &api.GetCertificatesInput{
			CAType: input.CAType,
			CAName: input.CAName,
			QueryParameters: common.QueryParameters{
				Pagination: common.PaginationOptions{
					Limit:  limit,
					Offset: i * limit,
				},
			},
		})
		if err != nil {
			return &output, err
		}
		if len(certsOutput.Certificates) == 0 {
			break
		}

		certificates = append(certificates, certsOutput.Certificates...)
		i++
	}

	for _, v := range certificates {
		input.PredicateFunc(&v)
	}

	return &output, nil
}

func (v *VaultSecrets) CheckAndUpdateCACertificateStatus(ctx context.Context, input *api.CheckAndUpdateCACertificateStatusInput) (*api.CheckAndUpdateCACertificateStatusOutput, error) {
	ca, err := v.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})
	if err != nil {
		return &api.CheckAndUpdateCACertificateStatusOutput{}, err
	}

	v.IterateCertificatesWithPredicate(ctx, &api.IterateCertificatesWithPredicateInput{
		CAType: input.CAType,
		CAName: input.CAName,
		PredicateFunc: func(c *api.Certificate) {
			if c.Status != api.StatusExpired && c.Status != api.StatusRevoked {
				if time.Until(c.Certificate.NotAfter) < 0 {
					v.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
						CAType:                  input.CAType,
						CAName:                  input.CAName,
						CertificateSerialNumber: c.SerialNumber,
						Status:                  api.StatusExpired,
					})
				} else if time.Until(c.Certificate.NotAfter) < time.Duration(30*24*time.Hour) {
					v.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
						CAType:                  input.CAType,
						CAName:                  input.CAName,
						CertificateSerialNumber: c.SerialNumber,
						Status:                  api.StatusAboutToExpire,
					})
				}
			}
		},
	})

	if ca.Status != api.StatusExpired && ca.Status != api.StatusRevoked {
		if time.Until(ca.Certificate.Certificate.NotAfter) < 0 {
			v.UpdateCAStatus(ctx, &api.UpdateCAStatusInput{
				CAType: input.CAType,
				CAName: input.CAName,
				Status: api.StatusExpired,
			})
		} else if time.Until(ca.Certificate.Certificate.NotAfter) < time.Duration(30*24*time.Hour) {
			v.UpdateCAStatus(ctx, &api.UpdateCAStatusInput{
				CAType: input.CAType,
				CAName: input.CAName,
				Status: api.StatusAboutToExpire,
			})
		}
	}

	ca, err = v.GetCAByName(ctx, &api.GetCAByNameInput{
		CAType: input.CAType,
		CAName: input.CAName,
	})
	if err != nil {
		return &api.CheckAndUpdateCACertificateStatusOutput{}, err
	}
	return &api.CheckAndUpdateCACertificateStatusOutput{
		CACertificate: ca.CACertificate,
	}, nil
}

func DecodeCert(cert []byte) (x509.Certificate, error) {
	pemBlock, _ := pem.Decode(cert)
	if pemBlock == nil {
		err := errors.New("cannot find the next formatted block")
		// level.Error(vs.logger).Log("err", err)
		return x509.Certificate{}, err
	}
	if pemBlock.Type != "CERTIFICATE" || len(pemBlock.Headers) != 0 {
		err := errors.New("unmatched type of headers")
		// level.Error(vs.logger).Log("err", err)
		return x509.Certificate{}, err
	}
	caCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		// level.Error(vs.logger).Log("err", err, "msg", "Could not parse "+caName+" CA certificate")
		return x509.Certificate{}, err
	}
	return *caCert, nil
}

func (v *VaultSecrets) initPkiSecret(ctx context.Context, caType api.CAType, CAName string, enrollerTTL string) error {

	mountInput := vaultApi.MountInput{Type: "pki", Description: ""}

	err := v.client.Sys().Mount(v.pkiPath+api.ToVaultPath(string(caType))+CAName, &mountInput)

	if err != nil {
		level.Debug(v.logger).Log("err", err, "msg", "Could not create a new pki mount point on Vault")
		if strings.Contains(err.Error(), "path is already in use") {
			duplicationErr := &caerrors.DuplicateResourceError{
				ResourceType: "CA",
				ResourceId:   CAName,
			}
			return duplicationErr
		} else {
			return err
		}
	}
	_, err = v.client.Logical().Write(v.pkiPath+api.ToVaultPath(string(caType))+CAName+"/roles/enroller", map[string]interface{}{
		"allow_any_name":      true,
		"ttl":                 enrollerTTL + "h",
		"max_ttl":             enrollerTTL + "h",
		"key_type":            "any",
		"enforce_hostnames":   false,
		"use_csr_common_name": false,
		"use_csr_sans":        false,
	})

	if err != nil {
		level.Debug(v.logger).Log("err", err, "msg", "Could not create a new role for "+CAName+" CA on Vault")
		return err
	}
	_, err = v.client.Logical().Write(v.pkiPath+api.ToVaultPath(string(caType))+CAName+"/config/urls", map[string]interface{}{
		"ocsp_servers": []string{
			v.ocspUrl,
		},
	})

	if err != nil {
		level.Debug(v.logger).Log("err", err, "msg", "Could not configure OCSP information for "+CAName+" CA on Vault")
		return err
	}

	return nil
}
