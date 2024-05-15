package keystorager

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/sirupsen/logrus"
)

type VaultKV2Engine struct {
	kvv2Client *api.KVv2
	logger     *logrus.Entry
}

func NewVaultKV2Engine(logger *logrus.Entry, conf config.HashicorpVaultCryptoEngineConfig) (KeyStorager, error) {
	var err error
	log := logger.WithField("subsystem-provider", "Vault-KV2")
	address := fmt.Sprintf("%s://%s:%d", conf.Protocol, conf.Hostname, conf.Port)

	log.Debugf("configuring VaultKV2 Engine")

	vaultClientConf := api.DefaultConfig()
	httpClient, err := helpers.BuildHTTPClientWithTLSOptions(&http.Client{}, conf.TLSConfig)

	if err != nil {
		return nil, err
	}

	httpClient, err = helpers.BuildHTTPClientWithTracerLogger(httpClient, log)
	if err != nil {
		return nil, err
	}

	vaultClientConf.HttpClient = httpClient
	vaultClientConf.Address = address
	vaultClient, err := api.NewClient(vaultClientConf)

	if err != nil {
		log.Errorf("could not create Vault API client: %s", err)
		return nil, errors.New("could not create Vault API client: " + err.Error())
	}

	if conf.AutoUnsealEnabled {
		err = Unseal(log, vaultClient, conf.AutoUnsealKeys)
		if err != nil {
			log.Errorf("could not unseal Vault: %s", err)
			return nil, errors.New("could not unseal Vault: " + err.Error())
		}
	}

	err = Login(vaultClient, conf.RoleID, string(conf.SecretID))
	if err != nil {
		log.Errorf("could not login into Vault: %s", err)
		return nil, errors.New("could not login into Vault: " + err.Error())
	}

	mounts, err := vaultClient.Sys().ListMounts()
	if err != nil {
		return nil, err
	}

	hasMount := false

	for mountPath := range mounts {
		if mountPath == conf.MountPath {
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
		logger:     log,
	}, nil
}

func (s *VaultKV2Engine) Get(keyID string) ([]byte, error) {
	s.logger.Debugf("requesting key with ID [%s]", keyID)
	key, err := s.kvv2Client.Get(context.Background(), keyID)
	if err != nil {
		s.logger.Errorf("could not get private key: %s", err)
		return nil, errors.New("could not get private key")
	}

	s.logger.Debugf("successfully retrieved private key")

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

	return pemBytes, nil
}

func (s *VaultKV2Engine) Create(keyID string, key []byte) error {
	keyBase64 := base64.StdEncoding.EncodeToString(key)
	var keyMap = map[string]interface{}{
		"key": keyBase64,
	}

	_, err := s.kvv2Client.Put(context.Background(), keyID, keyMap)
	if err != nil {
		s.logger.Errorf("could not create key: %s", err)
		return err
	}

	s.logger.Debugf("key successfully generated")
	return nil
}

func (s *VaultKV2Engine) Delete(keyID string) error {
	err := s.kvv2Client.Delete(context.Background(), keyID)
	return err
}

// ---------------------
func CreateVaultSdkClient(httpClient *http.Client, vaultAddress string) (*api.Client, error) {
	conf := api.DefaultConfig()

	conf.HttpClient = httpClient
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", vaultAddress)
	return api.NewClient(conf)
}

func Unseal(logger *logrus.Entry, client *api.Client, unsealKeys []config.Password) error {

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
