package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/hashicorp/go-cleanhttp"
	vaultApi "github.com/hashicorp/vault/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
)

type VaultSecrets struct {
	client   *vaultApi.Client
	roleID   string
	secretID string
	pkiPath  string
	ocspUrl  string
}

func NewVaultService(address string, pkiPath string, roleID string, secretID string, CA string, unsealFile string, ocspUrl string) {

}

func NewVaultSecretsWithClient(client *vaultApi.Client, address string, pkiPath string, roleID string, secretID string, CA string, unsealFile string, ocspUrl string, logger log.Logger) (*VaultSecrets, error) {
	return &VaultSecrets{
		client:   client,
		pkiPath:  pkiPath,
		roleID:   roleID,
		secretID: secretID,
		ocspUrl:  ocspUrl,
	}, nil
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
	return nil, nil
}

func (v *VaultSecrets) CreateCA(ctx context.Context, input *api.CreateCAInput) (*api.CreateCAOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) GetCAs(ctx context.Context, input *api.GetCAsInput) (*api.GetCAsOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) GetCAByName(ctx context.Context, input *api.GetCAByNameInput) (*api.GetCAByNameOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (*api.UpdateCAStatusOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) RevokeCA(ctx context.Context, input *api.RevokeCAInput) (*api.RevokeCAOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) IterateCAsWithPredicate(ctx context.Context, input *api.IterateCAsWithPredicateInput) (*api.IterateCAsWithPredicateOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) SignCertificateRequest(ctx context.Context, input *api.SignCertificateRequestInput) (*api.SignCertificateRequestOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) RevokeCertificate(ctx context.Context, input *api.RevokeCertificateInput) (*api.RevokeCertificateOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) GetCertificateBySerialNumber(ctx context.Context, input *api.GetCertificateBySerialNumberInput) (*api.GetCertificateBySerialNumberOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) GetCertificates(ctx context.Context, input *api.GetCertificatesInput) (*api.GetCertificatesOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) UpdateCertificateStatus(ctx context.Context, input *api.UpdateCertificateStatusInput) (*api.UpdateCertificateStatusOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) IterateCertificatesWithPredicate(ctx context.Context, input *api.IterateCertificatesWithPredicateInput) (*api.IterateCertificatesWithPredicateOutput, error) {
	return nil, nil
}

func (v *VaultSecrets) CheckAndUpdateCACertificateStatus(ctx context.Context, input *api.CheckAndUpdateCACertificateStatusInput) (*api.CheckAndUpdateCACertificateStatusOutput, error) {
	return nil, nil
}
