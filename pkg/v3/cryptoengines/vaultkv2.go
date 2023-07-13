package cryptoengines

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	log "github.com/sirupsen/logrus"
)

type VaultKV2Engine struct {
	kvv2Client *api.KVv2
}

func NewVaultKV2Engine(conf config.HashicorpVaultCryptoEngineConfig) (CryptoEngine, error) {
	var err error

	address := fmt.Sprintf("%s://%s:%d", conf.Protocol, conf.Hostname, conf.Port)

	vaultClientConf := api.DefaultConfig()
	httpClient, err := helpers.BuildHTTPClientWithTLSOptions(&http.Client{}, conf.TLSConfig)

	if err != nil {
		return nil, err
	}

	httpClient, err = helpers.BuildHTTPClientWithloggger(httpClient, "Vault KV-V2")
	if err != nil {
		return nil, err
	}

	vaultClientConf.HttpClient = httpClient
	vaultClientConf.Address = address
	vaultClient, err := api.NewClient(vaultClientConf)

	if err != nil {
		return nil, errors.New("could not create Vault API client: " + err.Error())
	}

	if conf.AutoUnsealEnabled {
		err = Unseal(vaultClient, conf.AutoUnsealKeysFile)
		if err != nil {
			return nil, errors.New("could not unseal Vault: " + err.Error())
		}
	}

	err = Login(vaultClient, conf.RoleID, conf.SecretID)
	if err != nil {
		return nil, errors.New("could not login into Vault: " + err.Error())
	}

	mounts, err := vaultClient.Sys().ListMounts()
	if err != nil {
		return nil, err
	}

	hasMount := false

	for mountPath, _ := range mounts {
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
	}, nil
}

func (vaultCli *VaultKV2Engine) GetEngineConfig() models.CryptoEngineProvider {
	supportedKeyTypes := []models.SupportedKeyTypeInfo{}

	supportedKeyTypes = append(supportedKeyTypes, models.SupportedKeyTypeInfo{
		Type:        models.KeyType(x509.RSA),
		MinimumSize: 1024,
		MaximumSize: 4096,
	})

	supportedKeyTypes = append(supportedKeyTypes, models.SupportedKeyTypeInfo{
		Type:        models.KeyType(x509.ECDSA),
		MinimumSize: 256,
		MaximumSize: 512,
	})
	return models.CryptoEngineProvider{
		Type:              models.VaultKV2,
		SecurityLevel:     models.SL1,
		Provider:          "Hashicorp",
		Manufacturer:      "Hashicorp",
		Model:             "",
		SupportedKeyTypes: supportedKeyTypes,
	}
}

func (vaultCli *VaultKV2Engine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	log.Debugf("[cryptoengine.vaultkv2] requesting private key with ID [%s]", keyID)
	key, err := vaultCli.kvv2Client.Get(context.Background(), keyID)
	if err != nil {
		log.Errorf("[cryptoengine.vaultkv2] could not get private key: %s", err)
		return nil, errors.New("could not get private key")
	}
	log.Debugf("[cryptoengine.vaultkv2] successfully retrieved private key")

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
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
}

func (vaultCli *VaultKV2Engine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	log.Debugf("[cryptoengine.vaultkv2] creating RSA private key of size [%d] with ID [%s]", keySize, keyID)
	key, err := vaultCli.GetPrivateKeyByID(keyID)
	if key != nil {
		log.Warnf("[cryptoengine.vaultkv2] RSA private key already exists and will be overwritten: ", err)
		err = vaultCli.DeleteKey(keyID)
		if err != nil {
			return nil, err
		}
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Errorf("[cryptoengine.vaultkv2] could not create RSA private key: %s", err)
		return nil, err
	}

	//output, err := client.Logical().Write("secret/data/abd", inputData)
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})
	keyBase64 := b64.StdEncoding.EncodeToString([]byte(keyPem))

	var keyMap = map[string]interface{}{
		"key": keyBase64,
	}

	_, err = vaultCli.kvv2Client.Put(context.Background(), keyID, keyMap)
	if err != nil {
		log.Errorf("[cryptoengine.vaultkv2] could not create RSA key: %s", err)
		return nil, err
	}

	log.Debugf("[cryptoengine.vaultkv2] RSA key successfully generated")
	return key, nil
}

func (vaultCli *VaultKV2Engine) CreateECDSAPrivateKey(c elliptic.Curve, keyID string) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(c, rand.Reader)

	if err != nil {
		log.Error("Could not create RSA private key: ", err)
		return nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)

	if err != nil {
		log.Error("Could not create RSA private key: ", err)
		return nil, err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	keyBase64 := b64.StdEncoding.EncodeToString([]byte(keyPem))
	fmt.Println("curva elipticaaa")
	fmt.Println(keyBase64)

	var keyMap = map[string]interface{}{
		"key": keyBase64,
	}

	_, err = vaultCli.kvv2Client.Put(context.Background(), keyID+"eliptica", keyMap)

	return nil, err
}

func (vaultCli *VaultKV2Engine) ImportRSAPrivateKey(key *rsa.PrivateKey, keyID string) (crypto.Signer, error) {
	return nil, fmt.Errorf("TODO")
}

func (vaultCli *VaultKV2Engine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey, keyID string) (crypto.Signer, error) {
	return nil, fmt.Errorf("TODO")
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

func Unseal(client *api.Client, unsealFile string) error {
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
