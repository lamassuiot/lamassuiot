package vaultkv2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	vconfig "github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/config"
	hhelpers "github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
)

type VaultKV2Engine struct {
	softCryptoEngine *software.SoftwareCryptoEngine
	kvv2Client       *api.KVv2
	mountPath        string
	vaultClient      *api.Client
	logger           *logrus.Entry
}

func NewVaultKV2Engine(logger *logrus.Entry, conf config.CryptoEngineConfigAdapter[vconfig.HashicorpVaultSDK]) (cryptoengines.CryptoEngine, error) {
	var err error
	lVault := logger.WithField("subsystem-provider", "Vault-KV2")
	address := fmt.Sprintf("%s://%s:%d", conf.Config.Protocol, conf.Config.Hostname, conf.Config.Port)

	lVault.Debugf("configuring VaultKV2 Engine")

	vaultClientConf := api.DefaultConfig()
	httpClient, err := hhelpers.BuildHTTPClientWithTLSOptions(&http.Client{}, conf.Config.TLSConfig)

	if err != nil {
		return nil, err
	}

	httpClient, err = hhelpers.BuildHTTPClientWithTracerLogger(httpClient, lVault)
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

	if conf.Config.AutoUnsealEnabled {
		err = Unseal(vaultClient, conf.Config.AutoUnsealKeys, lVault)
		if err != nil {
			lVault.Errorf("could not unseal Vault: %s", err)
			return nil, errors.New("could not unseal Vault: " + err.Error())
		}
	}

	err = Login(vaultClient, conf.Config.RoleID, string(conf.Config.SecretID))
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
		if mountPath == fmt.Sprintf("%s/", conf.Config.MountPath) { //mountPath has a trailing slash
			hasMount = true
		}
	}

	if !hasMount {
		err = vaultClient.Sys().Mount(conf.Config.MountPath, &api.MountInput{
			Type: "kv-v2",
		})

		if err != nil {
			return nil, err
		}

	}

	kv2 := vaultClient.KVv2(conf.Config.MountPath)

	return &VaultKV2Engine{
		logger:           lVault,
		softCryptoEngine: software.NewSoftwareCryptoEngine(lVault),
		mountPath:        conf.Config.MountPath,
		vaultClient:      vaultClient,
		kvv2Client:       kv2,
	}, nil
}

func (engine *VaultKV2Engine) GetEngineConfig() models.CryptoEngineInfo {
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
					384,
					521,
				},
			},
		},
	}
}

func (engine *VaultKV2Engine) GetPrivateKeyByID(ctx context.Context, keyID string) (crypto.Signer, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("requesting private key with ID [%s]", keyID)
	key, err := engine.kvv2Client.Get(ctx, keyID)
	if err != nil {
		lFunc.Errorf("could not get private key: %s", err)
		return nil, errors.New("could not get private key")
	}
	lFunc.Debugf("successfully retrieved private key")

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

	return engine.softCryptoEngine.ParsePrivateKey(pemBytes)
}

func (engine *VaultKV2Engine) ListPrivateKeyIDs(ctx context.Context) ([]string, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("listing private keys")

	resp, err := engine.vaultClient.Logical().List(fmt.Sprintf("%s/metadata", engine.mountPath))
	if err != nil {
		return nil, fmt.Errorf("error making request to vault: %w", err)
	}

	if resp == nil {
		return []string{}, nil
	}

	if resp.Data == nil {
		return nil, errors.New("no data in response from vault")
	}

	if _, ok := resp.Data["keys"]; !ok {
		return nil, errors.New("no keys in response from vault")
	}

	var keys []string
	for _, key := range resp.Data["keys"].([]any) {
		keys = append(keys, key.(string))
	}

	lFunc.Debugf("successfully retrieved private keys")
	return keys, nil
}

func (engine *VaultKV2Engine) CreateRSAPrivateKey(ctx context.Context, keySize int) (string, crypto.Signer, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("creating RSA private key")

	_, key, err := engine.softCryptoEngine.CreateRSAPrivateKey(ctx, keySize)
	if err != nil {
		lFunc.Errorf("could not create RSA private key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("RSA key successfully generated")
	return engine.importKey(ctx, key)
}

func (engine *VaultKV2Engine) CreateECDSAPrivateKey(ctx context.Context, c elliptic.Curve) (string, crypto.Signer, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("creating ECDSA private key")

	_, key, err := engine.softCryptoEngine.CreateECDSAPrivateKey(ctx, c)
	if err != nil {
		lFunc.Errorf("could not create ECDSA private key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("ECDSA key successfully generated")
	return engine.importKey(ctx, key)
}

func (engine *VaultKV2Engine) ImportRSAPrivateKey(ctx context.Context, key *rsa.PrivateKey) (string, crypto.Signer, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("importing RSA private key")

	keyID, signer, err := engine.importKey(ctx, key)
	if err != nil {
		lFunc.Errorf("could not import RSA key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("RSA key successfully imported")
	return keyID, signer, nil
}

func (engine *VaultKV2Engine) ImportECDSAPrivateKey(ctx context.Context, key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("importing ECDSA private key")

	keyID, signer, err := engine.importKey(ctx, key)
	if err != nil {
		lFunc.Errorf("could not import ECDSA key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("ECDSA key successfully imported")
	return keyID, signer, nil
}

func (engine *VaultKV2Engine) importKey(ctx context.Context, key any) (string, crypto.Signer, error) {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)
	pubKey := key.(crypto.Signer).Public()

	keyID, err := engine.softCryptoEngine.EncodePKIXPublicKeyDigest(ctx, pubKey)
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	b64PemKey, err := engine.softCryptoEngine.MarshalAndEncodePKIXPrivateKey(ctx, key)
	if err != nil {
		lFunc.Errorf("could not marshal and encode private key: %s", err)
		return "", nil, err
	}

	var keyMap = map[string]interface{}{
		"key": b64PemKey,
	}

	_, err = engine.kvv2Client.Put(ctx, keyID, keyMap)
	if err != nil {
		lFunc.Errorf("could not save the private key in vault: %s", err)
		return "", nil, err
	}

	signer, err := engine.GetPrivateKeyByID(ctx, keyID)
	if err != nil {
		lFunc.Errorf("could not retrieve the private key from vault: %s", err)
		return "", nil, err
	}

	return keyID, signer, nil
}

func (engine *VaultKV2Engine) RenameKey(ctx context.Context, oldID, newID string) error {
	lFunc := chelpers.ConfigureLogger(ctx, engine.logger)
	key, err := engine.kvv2Client.Get(ctx, oldID)
	if err != nil {
		lFunc.Errorf("could not get private key: %s", err)
		return errors.New("could not get private key")
	}

	_, err = engine.kvv2Client.Put(ctx, newID, key.Data)
	if err != nil {
		lFunc.Errorf("could not save the private key in vault: %s", err)
		return err
	}

	err = engine.kvv2Client.Delete(ctx, oldID)
	if err != nil {
		lFunc.Errorf("could not delete the old key: %s", err)
		return err
	}

	return nil
}

func (engine *VaultKV2Engine) DeleteKey(ctx context.Context, keyID string) error {
	return engine.kvv2Client.Delete(ctx, keyID)
}

// ---------------------
func CreateVaultSdkClient(httpClient *http.Client, vaultAddress string) (*api.Client, error) {
	conf := api.DefaultConfig()

	conf.HttpClient = httpClient
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", vaultAddress)
	return api.NewClient(conf)
}

func Unseal(client *api.Client, unsealKeys []config.Password, logger *logrus.Entry) error {
	providedSharesCount := 0
	sealed := true

	for sealed {
		unsealStatusProgress, err := client.Sys().Unseal(string(unsealKeys[providedSharesCount]))
		if err != nil {
			logger.Error("Error while unsealing vault: ", err)
			return err
		}
		logger.Info("Unseal progress shares=" + strconv.Itoa(unsealStatusProgress.N) + " threshold=" + strconv.Itoa(unsealStatusProgress.T) + " remaining_shares=" + strconv.Itoa(unsealStatusProgress.Progress))

		providedSharesCount++
		if !unsealStatusProgress.Sealed {
			logger.Info("Vault is unsealed")
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
