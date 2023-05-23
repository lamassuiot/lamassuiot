package x509engines

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	vaultApi "github.com/hashicorp/vault/api"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	caerrors "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
	log "github.com/sirupsen/logrus"

	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
)

type Vaultx509Engine struct {
	client   *vaultApi.Client
	roleID   string
	secretID string
	pkiPath  string
	ocspUrl  string
	logger   log.Logger
}

func NewVaultx509Engine(address string, pkiPath string, roleID string, secretID string, CA string, autoUnsealEnabled bool, unsealFile string, ocspUrl string) (X509Engine, error) {
	client, err := CreateVaultSdkClient(address, CA)
	if err != nil {
		return nil, errors.New("Could not create Vault API client: " + err.Error())
	}

	if autoUnsealEnabled {
		err = Unseal(client, unsealFile)
		if err != nil {
			return nil, errors.New("Could not unseal Vault: " + err.Error())
		}
	}

	err = Login(client, roleID, secretID)
	if err != nil {
		return nil, errors.New("Could not login into Vault: " + err.Error())
	}

	svc := Vaultx509Engine{
		client:   client,
		pkiPath:  pkiPath,
		roleID:   roleID,
		secretID: secretID,
		ocspUrl:  ocspUrl,
	}

	return svc, nil
}

func NewVaultx509EngineWithClient(client *vaultApi.Client, address string, pkiPath string, roleID string, secretID string, CA string, unsealFile string, ocspUrl string) (X509Engine, error) {
	v := Vaultx509Engine{
		client:   client,
		pkiPath:  pkiPath,
		roleID:   roleID,
		secretID: secretID,
		ocspUrl:  ocspUrl,
	}

	return &v, nil
}

func CreateVaultSdkClient(vaultAddress string, vaultCaCertFilePath string) (*vaultApi.Client, error) {
	conf := vaultApi.DefaultConfig()
	httpClient := cleanhttp.DefaultPooledClient()
	httpTrasport := cleanhttp.DefaultPooledTransport()
	caPool := x509.NewCertPool()

	if strings.HasPrefix(vaultAddress, "https://") {
		vaultCAFile, err := os.ReadFile(vaultCaCertFilePath)
		if err != nil {
			return nil, err
		}

		caPool.AppendCertsFromPEM(vaultCAFile)
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

func (v Vaultx509Engine) CreateCA(input api.CreateCAInput) (*x509.Certificate, error) {
	if input.KeyMetadata.KeyType == api.RSA {
		input.KeyMetadata.KeyType = "rsa"
	} else if input.KeyMetadata.KeyType == api.ECDSA {
		input.KeyMetadata.KeyType = "ec"
	}
	err := v.initPkiSecret(input.CAType, input.Subject.CommonName, fmt.Sprint(input.IssuanceExpiration.Hour()))
	if err != nil {
		return nil, err
	}
	tuneOptions := map[string]interface{}{
		"max_lease_ttl": fmt.Sprint(input.IssuanceExpiration.Hour()) + "h",
	}
	_, err = v.client.Logical().Write("/sys/mounts/"+v.pkiPath+api.ToVaultPath(string(input.CAType))+input.Subject.CommonName+"/tune", tuneOptions)

	if err != nil {
		log.Error(fmt.Sprintf("Could not tune CA %s: ", input.Subject.CommonName), err)
		return nil, err
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
		"ttl":               fmt.Sprint(input.IssuanceExpiration.Hour()) + "h",
	}
	_, err = v.client.Logical().Write(v.pkiPath+api.ToVaultPath(string(input.CAType))+input.Subject.CommonName+"/root/generate/internal", options)

	if err != nil {
		log.Error(fmt.Sprintf("Could not intialize the root CA certificate for %s CA on Vault: ", input.Subject.CommonName), err)
		return nil, err
	}
	resp, err := v.client.Logical().Read(v.pkiPath + api.ToVaultPath(string(input.CAType)) + input.Subject.CommonName + "/cert/ca")

	if err != nil {
		log.Error("Could not read "+input.Subject.CommonName+" certificate from Vault: ", err)
		return nil, errors.New("could not read certificate from Vault")
	}

	if resp == nil {
		log.Error("Mount path for PKI " + input.Subject.CommonName + " does not have a root CA")
		return nil, errors.New("mount path for PKI does not have a root CA")
	}

	certBytes := []byte(resp.Data["certificate"].(string))
	cert, err := DecodeCert(certBytes)

	return &cert, nil
}

func (v Vaultx509Engine) GetEngineConfig() api.EngineProviderInfo {
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

func (v Vaultx509Engine) initPkiSecret(caType api.CAType, CAName string, enrollerTTL string) error {
	mountInput := vaultApi.MountInput{Type: "pki", Description: ""}

	err := v.client.Sys().Mount(v.pkiPath+api.ToVaultPath(string(caType))+CAName, &mountInput)

	if err != nil {
		log.Error("Could not create a new pki mount point on Vault: ", err)
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
		log.Error("Could not create a new role for "+CAName+" CA on Vault: ", err)
		return err
	}
	_, err = v.client.Logical().Write(v.pkiPath+api.ToVaultPath(string(caType))+CAName+"/config/urls", map[string]interface{}{
		"ocsp_servers": []string{
			v.ocspUrl,
		},
	})

	if err != nil {
		log.Error("Could not configure OCSP information for "+CAName+" CA on Vault: ", err)
		return err
	}

	return nil
}

// falta meter el CACertificates en output + insert en BD
func (v Vaultx509Engine) SignCertificateRequest(caCertificate *x509.Certificate, certificateExpiration time.Time, input *api.SignCertificateRequestInput) (*x509.Certificate, error) {
	var err error

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
		return nil, notFoundErr
	}
	certData := data.Data["certificate"]
	certPEMBlock, _ := pem.Decode([]byte(certData.(string)))
	if certPEMBlock == nil || certPEMBlock.Type != "CERTIFICATE" {
		err = errors.New("failed to decode PEM block containing certificate")
		return nil, err
	}
	caCert := data.Data["issuing_ca"]
	caCertPEMBlock, _ := pem.Decode([]byte(caCert.(string)))
	if caCertPEMBlock == nil || caCertPEMBlock.Type != "CERTIFICATE" {
		err = errors.New("failed to decode PEM block containing certificate")
		return nil, err
	}
	certificate, err := x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	return certificate, nil
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
