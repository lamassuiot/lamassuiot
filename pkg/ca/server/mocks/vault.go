package mocks

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/secrets"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/logical/pki"
	"github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

type VaultSecretsMock struct {
	Client  *api.Client
	secrets secrets.Secrets
}

var (
	//Client
	errInvalidCA = errors.New("invalid CA, does not exist")

	//Server
	ErrGetCAs    = errors.New("unable to get CAs from secret engine")
	errGetCAInfo = errors.New("unable to get CA information from secret engine")
	errDeleteCA  = errors.New("unable to delete CA from secret engine")
)

func NewVaultSecretsMock(t *testing.T) (*api.Client, error) {
	t.Helper()

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}

	core, keyShares, rootToken := vault.TestCoreUnsealedWithConfig(t, coreConfig)
	_ = keyShares

	_, addr := http.TestServer(t, core)

	conf := api.DefaultConfig()
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", addr)

	client, err := api.NewClient(conf)
	if err != nil {
		return nil, err
	}
	client.SetToken(rootToken)

	//Mount CA PKI Backend
	_, err = client.Logical().Write("sys/mounts/Lamassu-Root-CA1-RSA4096", map[string]interface{}{
		"type": "pki",
		"config": map[string]interface{}{
			"max_lease_ttl": "262800h",
		},
	})
	if err != nil {
		return nil, err
	}

	//Setup CA Role
	_, err = client.Logical().Write("Lamassu-Root-CA1-RSA4096/roles/enroller", map[string]interface{}{
		"allow_any_name": true,
		"max_ttl":        "262800h",
		"key_type":       "any",
	})
	if err != nil {
		return nil, err
	}

	//Setup CA internal root certificate
	_, err = client.Logical().Write("Lamassu-Root-CA1-RSA4096/root/generate/internal", map[string]interface{}{
		"common_name":  "LKS Next Root CA 1",
		"key_type":     "RSA",
		"key_bits":     "4096",
		"organization": "LKS Next S. Coop",
		"country":      "ES",
		"ttl":          "262800h",
		"province":     "Gipuzkoa",
		"locality":     "Arrasate",
	})
	if err != nil {
		return nil, err
	}

	return client, err
}

//TODO:
func (vm *VaultSecretsMock) CreateCA(ctx context.Context, caType dto.CAType, caName string, ca dto.Cert) (dto.Cert, error) {
	return dto.Cert{}, nil
}

/*func (vm *VaultSecretsMock) GetCAs() (dto.Certs, error) {
	resp, err := vm.client.Sys().ListMounts()
	if err != nil {
		return dto.Certs{}, err
	}
	var CAs []dto.Certs
	for mount, mountOutput := range resp {
		if mountOutput.Type == "pki" {
			CAs = append(CAs, dto.Certs{Name: strings.TrimSuffix(mount, "/")})
		}
	}
	return dto.Certs{Certs: CAs}, nil
}*/

/*func (vm *VaultSecretsMock) GetCAInfo(CA string) (secrets.CAInfo, error) {
	caPath := CA + "/cert/ca"
	resp, err := vm.client.Logical().Read(caPath)
	if resp == nil {
		return secrets.CAInfo{}, nil
	}
	if err != nil {
		return secrets.CAInfo{}, err
	}
	pemBlock, _ := pem.Decode([]byte(resp.Data["certificate"].(string)))
	if pemBlock == nil {
		return secrets.CAInfo{}, errors.New("Cannot find the next PEM formatted block")
	}
	if pemBlock.Type != "CERTIFICATE" || len(pemBlock.Headers) != 0 {
		return secrets.CAInfo{}, errors.New("Unmatched type of headers")
	}
	caCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return secrets.CAInfo{}, err
	}
	key := caCert.PublicKeyAlgorithm.String()
	var keyBits int
	switch key {
	case "RSA":
		keyBits = caCert.PublicKey.(*rsa.PublicKey).N.BitLen()
	case "ECDSA":
		keyBits = caCert.PublicKey.(*ecdsa.PublicKey).Params().BitSize
	}
	CAInfo := secrets.CAInfo{
		C:       strings.Join(caCert.Subject.Country, " "),
		L:       strings.Join(caCert.Subject.Locality, " "),
		O:       strings.Join(caCert.Subject.Organization, " "),
		OU:      strings.Join(caCert.Subject.OrganizationalUnit, " "),
		ST:      strings.Join(caCert.Subject.Province, " "),
		CN:      caCert.Subject.CommonName,
		KeyType: key,
		KeyBits: keyBits,
	}
	return CAInfo, nil
}*/

func (vm *VaultSecretsMock) DeleteCA(ctx context.Context, caType dto.CAType, caName string) error {
	deletePath := caName + "/root"
	_, err := vm.Client.Logical().Delete(deletePath)
	if err != nil {
		return err
	}
	return nil
}

func (vm *VaultSecretsMock) DeleteCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) error {
	err := vm.secrets.DeleteCA(ctx, caType, caName)
	if err != nil {
		return err
	}
	return nil
}
func (vm *VaultSecretsMock) GetCA(ctx context.Context, caType dto.CAType, caName string) (dto.Cert, error) {
	return dto.Cert{}, nil
}

func (vm *VaultSecretsMock) GetCAs(ctx context.Context, caType dto.CAType) ([]dto.Cert, error) {

	CAs, err := vm.secrets.GetCAs(ctx, caType)

	if err != nil {
		var a []dto.Cert
		return a, ErrGetCAs
	}

	return CAs, nil

}

func (vm *VaultSecretsMock) GetCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) (dto.Cert, error) {
	certs, err := vm.secrets.GetCert(ctx, caType, caName, serialNumber)
	if err != nil {
		return dto.Cert{}, err
	}
	return certs, nil
}

func (vm *VaultSecretsMock) ImportCA(ctx context.Context, caType dto.CAType, caName string, certificate x509.Certificate, privateKey dto.PrivateKey, enrollerTTL int) (dto.Cert, error) {
	a, err := vm.secrets.ImportCA(ctx, caType, caName, certificate, privateKey, enrollerTTL)
	if err != nil {
		var b dto.Cert
		return b, err
	}
	return a, nil
}

func (vm *VaultSecretsMock) GetIssuedCerts(ctx context.Context, caType dto.CAType, caName string) ([]dto.Cert, error) {
	certs, err := vm.secrets.GetIssuedCerts(ctx, caType, caName, nil)
	if err != nil {
		var a []dto.Cert
		return a, err
	}
	return certs, nil
}

func (vm *VaultSecretsMock) GetSecretProviderName(ctx context.Context) string {
	return vm.secrets.GetSecretProviderName(ctx)
}

func (vm *VaultSecretsMock) SignCertificate(ctx context.Context, caType dto.CAType, caName string, csr *x509.CertificateRequest, signVerbatim bool) (string, error) {
	cert, err := vm.secrets.SignCertificate(ctx, caType, caName, csr, signVerbatim)
	if err != nil {
		return "", err
	}
	return cert.Crt, nil
}
