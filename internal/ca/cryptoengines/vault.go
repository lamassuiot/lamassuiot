package cryptoengines

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	"github.com/hashicorp/vault/api"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/helppers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	log "github.com/sirupsen/logrus"
)

type VaultCryptoEngine struct {
	client   *api.Client
	kv2      *api.KVv2
	roleID   string
	secretID string
}

func NewVaultCryptoEngine(conf config.HashicorpVaultCryptoEngineConfig) (CryptoEngine, error) {
	var extraCAFiles = []string{}
	var err error

	if !conf.InsecureSkipVerify && conf.CACertificateFile != "" {
		extraCAFiles = append(extraCAFiles, conf.CACertificateFile)
	}

	caPool := helppers.LoadSytemCACertPoolWithExtraCAsFromFiles(extraCAFiles)

	address := fmt.Sprintf("%s://%s:%d", conf.Protocol, conf.Hostname, conf.Port)
	vaultClientConf := api.DefaultConfig()

	httpClient := &http.Client{}
	httpTrasport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: conf.InsecureSkipVerify,
			RootCAs:            caPool,
		},
	}

	httpClient.Transport = httpTrasport

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
		if mountPath == "lamassu-engine/" {
			hasMount = true
		}
	}

	if !hasMount {
		err = vaultClient.Sys().Mount("lamassu-engine", &api.MountInput{
			Type: "kv-v2",
		})
		if err != nil {
			return nil, err
		}
	}

	kv2 := vaultClient.KVv2("lamassu-engine")

	svc := &VaultCryptoEngine{
		client:   vaultClient,
		roleID:   conf.RoleID,
		secretID: conf.SecretID,
		kv2:      kv2,
	}

	return svc, nil
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
			err = fmt.Errorf("error while unsealing vault: %w", err)
			log.Error(err)
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

func (engine *VaultCryptoEngine) GetEngineConfig() models.CryptoEngineProvider {
	return models.CryptoEngineProvider{}
}

func (engine *VaultCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	secret, err := engine.kv2.Get(context.Background(), keyID)
	if err != nil {
		return nil, err
	}

	rawB64Key := secret.Data["key"].(string)
	if rawB64Key == "" {
		return nil, fmt.Errorf("private key cannot be empty")
	}

	pemBytes, err := base64.RawStdEncoding.DecodeString(rawB64Key)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no key found")
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

func (engine *VaultCryptoEngine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Error("Could not create RSA private key: ", err)
		return nil, err
	}

	keyBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(key),
		Type:  "RSA PRIVATE KEY",
	})

	b64Key := base64.StdEncoding.EncodeToString(keyBytes)

	_, err = engine.kv2.Put(context.Background(), keyID, map[string]interface{}{
		"key": b64Key,
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (engine *VaultCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Error("Could not create ECDSA private key: ", err)
		return nil, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyBytes = pem.EncodeToMemory(&pem.Block{
		Bytes: keyBytes,
		Type:  "EC PRIVATE KEY",
	})

	b64Key := base64.StdEncoding.EncodeToString(keyBytes)

	_, err = engine.kv2.Put(context.Background(), keyID, map[string]interface{}{
		"key": b64Key,
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (engine *VaultCryptoEngine) DeleteAllKeys() error {
	return fmt.Errorf("TODO")
}
