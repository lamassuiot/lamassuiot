package vaultkv2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/sirupsen/logrus"
)

const (
	RSA_PRIVATE_KEY string = "RSA PRIVATE KEY"
	ECC_PRIVATE_KEY string = "EC PRIVATE KEY"
)

var lVault *logrus.Entry

type VaultKV2Engine struct {
	kvv2Client *api.KVv2
}

func NewVaultKV2Engine(logger *logrus.Entry, conf config.HashicorpVaultCryptoEngineConfig) (cryptoengines.CryptoEngine, error) {
	var err error
	lVault = logger.WithField("subsystem-provider", "Vault-KV2")
	address := fmt.Sprintf("%s://%s:%d", conf.Protocol, conf.Hostname, conf.Port)

	lVault.Debugf("configuring VaultKV2 Engine")

	vaultClientConf := api.DefaultConfig()
	httpClient, err := helpers.BuildHTTPClientWithTLSOptions(&http.Client{}, conf.TLSConfig)

	if err != nil {
		return nil, err
	}

	httpClient, err = helpers.BuildHTTPClientWithTracerLogger(httpClient, lVault)
	if err != nil {
		return nil, err
	}

	vaultClientConf.HttpClient = httpClient
	vaultClientConf.Address = address
	vaultClient, err := api.NewClient(vaultClientConf)

	if err != nil {
		lVault.Errorf("could not create Vault API client: %s", err)
		return nil, errors.New("could not create Vault API client: " + err.Error())
	}

	if conf.AutoUnsealEnabled {
		err = Unseal(vaultClient, conf.AutoUnsealKeys)
		if err != nil {
			lVault.Errorf("could not unseal Vault: %s", err)
			return nil, errors.New("could not unseal Vault: " + err.Error())
		}
	}

	err = Login(vaultClient, conf.RoleID, string(conf.SecretID))
	if err != nil {
		lVault.Errorf("could not login into Vault: %s", err)
		return nil, errors.New("could not login into Vault: " + err.Error())
	}

	mounts, err := vaultClient.Sys().ListMounts()
	if err != nil {
		return nil, err
	}

	hasMount := false

	for mountPath := range mounts {
		if mountPath == fmt.Sprintf("%s/", conf.MountPath) { //mountPath has a trailing slash
			hasMount = true
		}
	}

	if !hasMount {
		err = vaultClient.Sys().Mount(conf.MountPath, &api.MountInput{
			Type: "kv-v2",
		})

		if err != nil {
			return nil, err
		}
	}

	kv2 := vaultClient.KVv2(conf.MountPath)

	return &VaultKV2Engine{
		kvv2Client: kv2,
	}, nil
}

func (vaultCli *VaultKV2Engine) GetEngineConfig() models.CryptoEngineInfo {
	return models.CryptoEngineInfo{
		Type:          models.VaultKV2,
		SecurityLevel: models.SL1,
		Provider:      "Hashicorp",
		Name:          "Key Value - V2",
		Metadata:      map[string]any{},
		SupportedKeyTypes: []models.SupportedKeyTypeInfo{
			{
				Type: models.KeyType(x509.RSA),
				Sizes: []int{
					2048,
					3072,
					4096,
				},
			},
			{
				Type: models.KeyType(x509.ECDSA),
				Sizes: []int{
					224,
					256,
					521,
				},
			},
		},
	}
}

func (vaultCli *VaultKV2Engine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	lVault.Debugf("requesting private key with ID [%s]", keyID)
	key, err := vaultCli.kvv2Client.Get(context.Background(), keyID)
	if err != nil {
		lVault.Errorf("could not get private key: %s", err)
		return nil, errors.New("could not get private key")
	}
	lVault.Debugf("successfully retrieved private key")

	var b64Key string
	mapValue, ok := key.Data["key"]
	if !ok {
		return nil, fmt.Errorf("'key' not found in secret")
	}

	if b64Key, ok = mapValue.(string); !ok {
		return nil, fmt.Errorf("'key' not in string format")
	}

	pemBytes, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no key found")
	}

	switch block.Type {
	case RSA_PRIVATE_KEY:
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case ECC_PRIVATE_KEY:
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
}

func (vaultCli *VaultKV2Engine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	lVault.Debugf("creating RSA private key of size [%d] with ID [%s]", keySize, keyID)
	key, err := vaultCli.GetPrivateKeyByID(keyID)
	if key != nil {
		lVault.Warnf("RSA private key already exists and will be overwritten: %s", err)
		err = vaultCli.DeleteKey(keyID)
		if err != nil {
			return nil, err
		}
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		lVault.Errorf("could not create RSA private key: %s", err)
		return nil, err
	}

	//output, err := client.Logical().Write("secret/data/abd", inputData)
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  RSA_PRIVATE_KEY,
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})
	keyBase64 := base64.StdEncoding.EncodeToString([]byte(keyPem))

	var keyMap = map[string]interface{}{
		"key": keyBase64,
	}

	_, err = vaultCli.kvv2Client.Put(context.Background(), keyID, keyMap)
	if err != nil {
		lVault.Errorf("could not create RSA key: %s", err)
		return nil, err
	}

	lVault.Debugf("RSA key successfully generated")
	return rsaKey, nil
}

func (vaultCli *VaultKV2Engine) CreateECDSAPrivateKey(c elliptic.Curve, keyID string) (crypto.Signer, error) {
	lVault.Debugf("creating ECDSA private key of size [%d] with ID [%s]", c.Params().BitSize, keyID)
	key, err := ecdsa.GenerateKey(c, rand.Reader)

	if err != nil {
		lVault.Errorf("Could not create RSA private key: %s", err)
		return nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)

	if err != nil {
		lVault.Errorf("Could not create RSA private key: %s", err)
		return nil, err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{Type: ECC_PRIVATE_KEY, Bytes: keyBytes})

	keyBase64 := base64.StdEncoding.EncodeToString([]byte(keyPem))

	var keyMap = map[string]interface{}{
		"key": keyBase64,
	}

	_, err = vaultCli.kvv2Client.Put(context.Background(), keyID, keyMap)

	return key, err
}

func (vaultCli *VaultKV2Engine) ImportRSAPrivateKey(key *rsa.PrivateKey, keyID string) (crypto.Signer, error) {
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  RSA_PRIVATE_KEY,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	keyBase64 := base64.StdEncoding.EncodeToString([]byte(keyPem))

	var keyMap = map[string]interface{}{
		"key": keyBase64,
	}

	_, err := vaultCli.kvv2Client.Put(context.Background(), keyID, keyMap)
	if err != nil {
		lVault.Errorf("could not save the private key in vault: %s", err)
		return nil, err
	}

	lVault.Debugf("RSA key successfully imported")

	return vaultCli.GetPrivateKeyByID(keyID)
}

func (vaultCli *VaultKV2Engine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey, keyID string) (crypto.Signer, error) {
	keyBytes, err := x509.MarshalECPrivateKey(key)

	if err != nil {
		lVault.Errorf("Could not create RSA private key: %s", err)
		return nil, err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{Type: ECC_PRIVATE_KEY, Bytes: keyBytes})

	keyBase64 := base64.StdEncoding.EncodeToString([]byte(keyPem))

	var keyMap = map[string]interface{}{
		"key": keyBase64,
	}

	_, err = vaultCli.kvv2Client.Put(context.Background(), keyID, keyMap)

	if err != nil {
		lVault.Errorf("Could not save the private key in vault: %s", err)
		return nil, err
	}

	lVault.Debugf("ECDSA key successfully imported")

	return vaultCli.GetPrivateKeyByID(keyID)
}

func (vaultCli *VaultKV2Engine) DeleteKey(keyID string) error {
	err := vaultCli.kvv2Client.Delete(context.Background(), keyID)
	return err
}

// ---------------------
func CreateVaultSdkClient(httpClient *http.Client, vaultAddress string) (*api.Client, error) {
	conf := api.DefaultConfig()

	conf.HttpClient = httpClient
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", vaultAddress)
	return api.NewClient(conf)
}

func Unseal(client *api.Client, unsealKeys []config.Password) error {

	providedSharesCount := 0
	sealed := true

	for sealed {
		unsealStatusProgress, err := client.Sys().Unseal(string(unsealKeys[providedSharesCount]))
		if err != nil {
			lVault.Error("Error while unsealing vault: ", err)
			return err
		}
		lVault.Info("Unseal progress shares=" + strconv.Itoa(unsealStatusProgress.N) + " threshold=" + strconv.Itoa(unsealStatusProgress.T) + " remaining_shares=" + strconv.Itoa(unsealStatusProgress.Progress))

		providedSharesCount++
		if !unsealStatusProgress.Sealed {
			lVault.Info("Vault is unsealed")
			sealed = false
		}
	}
	return nil
}

func Login(client *api.Client, roleID string, secretID string) error {
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
