package cryptoengines

import (
	"crypto"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
	vaultApi "github.com/hashicorp/vault/api"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	log "github.com/sirupsen/logrus"
)

type VaultCryptoEngine struct {
	client   *vaultApi.Client
	roleID   string
	secretID string
}

func NewVaultCryptoEngine(address string, roleID string, secretID string, CACert *x509.Certificate, insecure bool, autoUnsealEnabled bool, unsealFile string) (CryptoEngine, error) {
	client, err := CreateVaultSdkClient(address, CACert)
	if err != nil {
		return nil, errors.New("could not create Vault API client: " + err.Error())
	}

	if autoUnsealEnabled {
		err = Unseal(client, unsealFile)
		if err != nil {
			return nil, errors.New("could not unseal Vault: " + err.Error())
		}
	}

	err = Login(client, roleID, secretID)
	if err != nil {
		return nil, errors.New("could not login into Vault: " + err.Error())
	}

	svc := &VaultCryptoEngine{
		client:   client,
		roleID:   roleID,
		secretID: secretID,
	}

	return svc, nil
}

func CreateVaultSdkClient(vaultAddress string, CACert *x509.Certificate) (*vaultApi.Client, error) {
	conf := vaultApi.DefaultConfig()
	httpClient := cleanhttp.DefaultPooledClient()
	httpTrasport := cleanhttp.DefaultPooledTransport()
	caPool := x509.NewCertPool()

	if CACert != nil {
		caPool.AddCert(CACert)
	}

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

func Unseal(client *vaultApi.Client, unsealFile string) error {
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
			log.Error("Error while unsealing vault: ", err)
			return err
		}
		log.Info("Unseal progress shares=" + strconv.Itoa(unsealStatusProgress.N) + " threshold=" + strconv.Itoa(unsealStatusProgress.T) + " remaining_shares=" + strconv.Itoa(unsealStatusProgress.Progress))

		providedSharesCount++
		if !unsealStatusProgress.Sealed {
			log.Info("Vault is unsealed")
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

func (engine *VaultCryptoEngine) GetEngineConfig() models.CryptoEngineProvider {
	return models.CryptoEngineProvider{}
}

func (engine *VaultCryptoEngine) GetPrivateKeys() ([]crypto.Signer, error) {
	return []crypto.Signer{}, fmt.Errorf("TODO")
}

func (engine *VaultCryptoEngine) GetPrivateKeyByID(string) (crypto.Signer, error) {
	return nil, fmt.Errorf("TODO")
}

func (engine *VaultCryptoEngine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	return nil, fmt.Errorf("TODO")
}

func (engine *VaultCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	return nil, fmt.Errorf("TODO")
}

func (engine *VaultCryptoEngine) DeleteAllKeys() error {
	return fmt.Errorf("TODO")
}
