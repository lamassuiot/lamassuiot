package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	lamassuErrors "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/models/ca"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/opentracing/opentracing-go"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/api"
)

type VaultSecrets struct {
	client   *api.Client
	roleID   string
	secretID string
	pkiPath  string
	ocspUrl  string
}

func NewVaultSecrets(address string, pkiPath string, roleID string, secretID string, CA string, unsealFile string, ocspUrl string, logger log.Logger) (*VaultSecrets, error) {

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

	return &VaultSecrets{
		client:   client,
		pkiPath:  pkiPath,
		roleID:   roleID,
		secretID: secretID,
		ocspUrl:  ocspUrl,
	}, nil
}

func NewVaultSecretsWithClient(client *api.Client, address string, pkiPath string, roleID string, secretID string, CA string, unsealFile string, ocspUrl string, logger log.Logger) (*VaultSecrets, error) {
	return &VaultSecrets{
		client:   client,
		pkiPath:  pkiPath,
		roleID:   roleID,
		secretID: secretID,
		ocspUrl:  ocspUrl,
	}, nil
}

func CreateVaultSdkClient(vaultAddress string, vaultCaCertFilePath string, logger log.Logger) (*api.Client, error) {
	conf := api.DefaultConfig()
	httpClient := cleanhttp.DefaultPooledClient()
	httpTrasport := cleanhttp.DefaultPooledTransport()
	caPool, err := utils.CreateCAPool(vaultCaCertFilePath)

	if err != nil {
		return nil, err
	}

	httpTrasport.TLSClientConfig = &tls.Config{
		RootCAs: caPool,
	}
	httpClient.Transport = httpTrasport
	conf.HttpClient = httpClient
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", vaultAddress)
	// tlsConf := &api.TLSConfig{CACert: CA}
	// conf.ConfigureTLS(tlsConf)
	return api.NewClient(conf)

}

func Unseal(client *api.Client, unsealFile string, logger log.Logger) error {
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

func (vs *VaultSecrets) GetSecretProviderName(ctx context.Context) string {
	return "Hashicorp_Vault"
}

func (vs *VaultSecrets) SignCertificate(ctx context.Context, caType dto.CAType, caName string, csr *x509.CertificateRequest, signVerbatim bool) (dto.SignResponse, error) {
	csrBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	options := map[string]interface{}{
		"csr":         string(csrBytes),
		"common_name": csr.Subject.CommonName,
	}

	parentSpan := opentracing.SpanFromContext(ctx)
	var data *api.Secret
	var err error
	if signVerbatim {
		span := opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/sign-verbatim/enroller", opentracing.ChildOf(parentSpan.Context()))
		data, err = vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+caName+"/sign-verbatim/enroller", options)
		span.Finish()
	} else {
		options["exclude_cn_from_sans"] = true
		span := opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/sign/enroller", opentracing.ChildOf(parentSpan.Context()))
		data, err = vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+caName+"/sign/enroller", options)
		span.Finish()
	}
	if err != nil {
		return dto.SignResponse{}, err
	}
	certData := data.Data["certificate"]
	certPEMBlock, _ := pem.Decode([]byte(certData.(string)))
	if certPEMBlock == nil || certPEMBlock.Type != "CERTIFICATE" {
		err = errors.New("failed to decode PEM block containing certificate")
		return dto.SignResponse{}, err
	}
	caCert := data.Data["issuing_ca"]
	caCertPEMBlock, _ := pem.Decode([]byte(caCert.(string)))
	if caCertPEMBlock == nil || caCertPEMBlock.Type != "CERTIFICATE" {
		err = errors.New("failed to decode PEM block containing certificate")
		return dto.SignResponse{}, err
	}
	certs := dto.SignResponse{
		Crt:   base64.StdEncoding.EncodeToString([]byte(certData.(string))),
		CaCrt: base64.StdEncoding.EncodeToString([]byte(caCert.(string))),
	}
	return certs, nil
}

func (vs *VaultSecrets) GetCA(ctx context.Context, caType dto.CAType, caName string) (dto.Cert, error) {
	logger := ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api GET /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/cert/ca", opentracing.ChildOf(parentSpan.Context()))
	resp, err := vs.client.Logical().Read(vs.pkiPath + caType.ToVaultPath() + caName + "/cert/ca")
	span.Finish()

	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Could not read "+caName+" certificate from Vault")
		return dto.Cert{}, errors.New("could not read certificate from Vault")
	}
	if resp == nil {
		level.Debug(logger).Log("Mount path for PKI " + caName + " does not have a root CA")
		return dto.Cert{}, errors.New("mount path for PKI does not have a root CA")
	}

	certBytes := []byte(resp.Data["certificate"].(string))
	cert, err := DecodeCert(certBytes)
	if err != nil {
		err = errors.New("cannot decode cert. Perhaps it is malphormed")
		level.Debug(logger).Log("err", err)
		return dto.Cert{}, err
	}
	pubKey, keyType, keyBits, keyStrength := getPublicKeyInfo(cert)
	hasExpired := cert.NotAfter.Before(time.Now())
	status := "issued"
	if hasExpired {
		status = "expired"
	}

	if !vs.hasEnrollerRole(ctx, caType, caName) {
		status = "revoked"
	}

	return dto.Cert{
		SerialNumber: utils.InsertNth(utils.ToHexInt(cert.SerialNumber), 2),
		Status:       status,
		Name:         caName,
		CertContent: dto.CertContent{
			CerificateBase64: base64.StdEncoding.EncodeToString([]byte(resp.Data["certificate"].(string))),
			PublicKeyBase64:  base64.StdEncoding.EncodeToString([]byte(pubKey)),
		},
		Subject: dto.Subject{
			C:  strings.Join(cert.Subject.Country, " "),
			ST: strings.Join(cert.Subject.Province, " "),
			L:  strings.Join(cert.Subject.Locality, " "),
			O:  strings.Join(cert.Subject.Organization, " "),
			OU: strings.Join(cert.Subject.OrganizationalUnit, " "),
			CN: cert.Subject.CommonName,
		},
		KeyMetadata: dto.PrivateKeyMetadataWithStregth{
			KeyType:     keyType.String(),
			KeyBits:     keyBits,
			KeyStrength: keyStrength,
		},
		ValidFrom: cert.NotBefore.String(),
		ValidTo:   cert.NotAfter.String(),
	}, nil
}

func (vs *VaultSecrets) GetCAs(ctx context.Context, caType dto.CAType) ([]dto.Cert, error) {
	logger := ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)

	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api GET /v1/sys/mounts", opentracing.ChildOf(parentSpan.Context()))
	resp, err := vs.client.Sys().ListMounts()
	span.Finish()

	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Could not obtain list of Vault mounts")
		return []dto.Cert{}, err
	}
	var cas []dto.Cert

	for mount, mountOutput := range resp {
		if mountOutput.Type == "pki" && strings.HasPrefix(mount, vs.pkiPath) {
			caName := strings.TrimSuffix(mount, "/")
			caName = strings.TrimPrefix(caName, vs.pkiPath)
			if strings.Contains(caName, caType.ToVaultPath()) {
				caName = strings.TrimPrefix(caName, caType.ToVaultPath())
				cert, err := vs.GetCA(ctx, caType, caName)
				if err != nil {
					level.Debug(logger).Log("err", err, "msg", "Could not get CA cert for "+caName)
					continue
				}
				cas = append(cas, cert)
			}
		}
	}
	level.Debug(logger).Log("msg", strconv.Itoa(len(cas))+" obtained from Vault mounts")
	return cas, nil
}

func (vs *VaultSecrets) CreateCA(ctx context.Context, caType dto.CAType, CAName string, privateKeyMetadata dto.PrivateKeyMetadata, subject dto.Subject, caTTL int, enrollerTTL int) (dto.Cert, error) {
	logger := ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)

	err := vs.initPkiSecret(ctx, caType, CAName, enrollerTTL)
	if err != nil {
		return dto.Cert{}, err
	}

	tuneOptions := map[string]interface{}{
		"max_lease_ttl": strconv.Itoa(caTTL) + "h",
	}
	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/sys/mounts/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/tune", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Write("/sys/mounts/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/tune", tuneOptions)
	span.Finish()

	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Could not tune CA "+CAName)
		return dto.Cert{}, err
	}

	options := map[string]interface{}{
		"key_type":          privateKeyMetadata.KeyType,
		"key_bits":          privateKeyMetadata.KeyBits,
		"country":           subject.C,
		"province":          subject.ST,
		"locality":          subject.L,
		"organization":      subject.O,
		"organization_unit": subject.OU,
		"common_name":       subject.CN,
		"ttl":               strconv.Itoa(caTTL) + "h",
	}
	span = opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/root/generate/internal", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+CAName+"/root/generate/internal", options)
	span.Finish()

	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Could not intialize the root CA certificate for "+CAName+" CA on Vault")
		return dto.Cert{}, err
	}

	return vs.GetCA(ctx, caType, CAName)
}

func (vs *VaultSecrets) ImportCA(ctx context.Context, caType dto.CAType, CAName string, certificate x509.Certificate, privateKey dto.PrivateKey, enrollerTTL int) (dto.Cert, error) {
	crtBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	privKeyString, err := privateKey.GetPEMString()
	if err != nil {
		return dto.Cert{}, err
	}

	err = vs.initPkiSecret(ctx, caType, CAName, enrollerTTL)
	if err != nil {
		return dto.Cert{}, err
	}

	options := map[string]interface{}{
		"pem_bundle": privKeyString + string(crtBytes),
	}

	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/config/ca", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+CAName+"/config/ca", options)
	span.Finish()

	if err != nil {
		return dto.Cert{}, err
	}

	return vs.GetCA(ctx, caType, CAName)
}

func (vs *VaultSecrets) initPkiSecret(ctx context.Context, caType dto.CAType, CAName string, enrollerTTL int) error {
	logger := ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)

	mountInput := api.MountInput{Type: "pki", Description: ""}

	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/sys/mounts/"+vs.pkiPath+caType.ToVaultPath()+CAName, opentracing.ChildOf(parentSpan.Context()))
	err := vs.client.Sys().Mount(vs.pkiPath+caType.ToVaultPath()+CAName, &mountInput)
	span.Finish()

	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Could not create a new pki mount point on Vault")
		if strings.Contains(err.Error(), "path is already in use") {
			duplicationErr := &lamassuErrors.DuplicateResourceError{
				ResourceType: "CA",
				ResourceId:   CAName,
			}
			return duplicationErr
		} else {
			return err
		}
	}
	span = opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/roles/enroller", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+CAName+"/roles/enroller", map[string]interface{}{
		"allow_any_name":    true,
		"ttl":               strconv.Itoa(enrollerTTL) + "h",
		"max_ttl":           strconv.Itoa(enrollerTTL) + "h",
		"key_type":          "any",
		"enforce_hostnames": false,
	})
	span.Finish()

	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Could not create a new role for "+CAName+" CA on Vault")
		return err
	}
	span = opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+CAName+"/config/urls", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+CAName+"/config/urls", map[string]interface{}{
		"ocsp_servers": []string{
			vs.ocspUrl,
		},
	})
	span.Finish()

	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Could not configure OCSP information for "+CAName+" CA on Vault")
		return err
	}

	return nil
}

func (vs *VaultSecrets) DeleteCA(ctx context.Context, caType dto.CAType, ca string) error {
	logger := ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	if len(ca) == 0 {
		err := errors.New("CA name not defined")
		return err
	}

	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api DELETE /v1/"+vs.pkiPath+caType.ToVaultPath()+ca+"/root", opentracing.ChildOf(parentSpan.Context()))
	_, err := vs.client.Logical().Delete(vs.pkiPath + caType.ToVaultPath() + ca + "/root")
	span.Finish()

	if err != nil {

		level.Debug(logger).Log("err", err, "msg", "Could not delete "+ca+" certificate from Vault")
		return errors.New("could not delete certificate from Vault")
	}
	span = opentracing.StartSpan("lamassu-ca-api: vault-api DELETE /v1/"+vs.pkiPath+caType.ToVaultPath()+ca+"/roles/enroller", opentracing.ChildOf(parentSpan.Context()))
	_, err = vs.client.Logical().Delete(vs.pkiPath + caType.ToVaultPath() + ca + "/roles/enroller")
	span.Finish()

	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Could not delete enroller role from CA "+ca)
		return errors.New("could not delete enroller role from CA")
	}
	return nil
}

func (vs *VaultSecrets) GetCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) (dto.Cert, error) {
	logger := ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	if len(serialNumber) <= 0 {
		return dto.Cert{}, errors.New("empty serial number")
	}
	span := opentracing.StartSpan("lamassu-ca-api: vault-api GET /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/cert/"+serialNumber, opentracing.ChildOf(parentSpan.Context()))
	certResponse, err := vs.client.Logical().Read(vs.pkiPath + caType.ToVaultPath() + caName + "/cert/" + serialNumber)
	span.Finish()

	if err != nil || certResponse == nil {
		level.Debug(logger).Log("err", err, "msg", "Could not read cert with serial number "+serialNumber+" from CA "+caName)
		return dto.Cert{}, errors.New("could not read cert from CA")
	}
	cert, err := DecodeCert([]byte(certResponse.Data["certificate"].(string)))
	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Could not decode certificate serial number "+serialNumber+" from CA "+caName)
		return dto.Cert{}, errors.New("could not decode cert from CA")
	}
	pubKey, keyType, keyBits, keyStrength := getPublicKeyInfo(cert)
	hasExpired := cert.NotAfter.Before(time.Now())
	status := "issued"
	if hasExpired {
		status = "expired"
	}
	revocation_time, err := certResponse.Data["revocation_time"].(json.Number).Int64()
	if err != nil {
		err = errors.New("revocation_time not an INT for cert " + serialNumber + ".")
		level.Warn(logger).Log("err", err)
	}
	if revocation_time != 0 {
		status = "revoked"
	}
	return dto.Cert{
		SerialNumber: utils.InsertNth(utils.ToHexInt(cert.SerialNumber), 2),
		Status:       status,
		Name:         caName,
		CertContent: dto.CertContent{
			CerificateBase64: base64.StdEncoding.EncodeToString([]byte(certResponse.Data["certificate"].(string))),
			PublicKeyBase64:  base64.StdEncoding.EncodeToString([]byte(pubKey)),
		},
		Subject: dto.Subject{
			C:  strings.Join(cert.Subject.Country, " "),
			ST: strings.Join(cert.Subject.Province, " "),
			L:  strings.Join(cert.Subject.Locality, " "),
			O:  strings.Join(cert.Subject.Organization, " "),
			OU: strings.Join(cert.Subject.OrganizationalUnit, " "),
			CN: cert.Subject.CommonName,
		},
		KeyMetadata: dto.PrivateKeyMetadataWithStregth{
			KeyType:     keyType.String(),
			KeyBits:     keyBits,
			KeyStrength: keyStrength,
		},
		ValidFrom:           cert.NotBefore.String(),
		ValidTo:             cert.NotAfter.String(),
		RevocationTimestamp: revocation_time,
	}, nil
}

func (vs *VaultSecrets) GetIssuedCerts(ctx context.Context, caType dto.CAType, caName string, serialnumbers []ca.IssuedCerts) ([]dto.Cert, error) {
	logger := ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)

	var certs []dto.Cert
	certs = make([]dto.Cert, 0)

	if caName == "" {
		cas, err := vs.GetCAs(ctx, caType)
		if err != nil {
			level.Debug(logger).Log("err", err, "msg", "Could not get CAs from Vault")
			return []dto.Cert{}, err
		}
		for _, cert := range cas {
			if cert.Name != "" {
				certsSubset, err := vs.GetIssuedCerts(ctx, caType, cert.Name, serialnumbers)
				if err != nil {
					level.Debug(logger).Log("err", err, "msg", "Error while getting issued cert subset for CA "+cert.Name)
					continue
				}
				certs = append(certs, certsSubset...)
			}
		}
	} else {
		parentSpan := opentracing.SpanFromContext(ctx)
		/*span := opentracing.StartSpan("lamassu-ca-api: vault-api LIST /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/certs", opentracing.ChildOf(parentSpan.Context()))
		resp, err := vs.client.Logical().List(vs.pkiPath + caType.ToVaultPath() + caName + "/certs")
		span.Finish()

		if err != nil {
			level.Debug(logger).Log("err", err, "msg", "Could not read "+caName+" mount path from Vault")
			return []dto.Cert{}, errors.New("could not read mount path from Vault")
		}*/

		caCert, err := vs.GetCA(ctx, caType, caName)
		if err != nil {
			level.Debug(logger).Log("err", err, "msg", "Could not get CA cert for "+caName)
			notFoundErr := &lamassuErrors.ResourceNotFoundError{
				ResourceType: "CA",
				ResourceId:   caName,
			}
			return []dto.Cert{}, notFoundErr
		}

		for _, elem := range serialnumbers {
			if len(caCert.SerialNumber) == 0 {
				err = errors.New("certificate without Serial Number")
				return []dto.Cert{}, err
			} else {
				if caCert.SerialNumber == elem.SerialNumber {
					continue
				}
				span := opentracing.StartSpan("lamassu-ca-api: vault-api GET /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/cert/"+elem.SerialNumber, opentracing.ChildOf(parentSpan.Context()))
				certResponse, err := vs.client.Logical().Read(vs.pkiPath + caType.ToVaultPath() + caName + "/cert/" + elem.SerialNumber)
				span.Finish()

				if err != nil || certResponse == nil {
					level.Debug(logger).Log("err", err, "msg", "Could not read certificate "+elem.SerialNumber+" from CA "+caName)
					continue
				}
				cert, err := DecodeCert([]byte(certResponse.Data["certificate"].(string)))
				if err != nil {
					err = errors.New("Cannot decode cert " + elem.SerialNumber + ". Perhaps it is malphormed")
					level.Debug(logger).Log("err", err)
					continue
				}

				pubKey, keyType, keyBits, keyStrength := getPublicKeyInfo(cert)
				hasExpired := cert.NotAfter.Before(time.Now())
				status := "issued"
				if hasExpired {
					status = "expired"
				}
				revocation_time, err := certResponse.Data["revocation_time"].(json.Number).Int64()
				if err != nil {
					err = errors.New("revocation_time not an INT for cert " + elem.SerialNumber + ".")
					level.Debug(logger).Log("err", err)
					continue
				}
				if revocation_time != 0 {
					status = "revoked"
				}

				certs = append(certs, dto.Cert{
					SerialNumber: utils.InsertNth(utils.ToHexInt(cert.SerialNumber), 2),
					Status:       status,
					Name:         caName,
					CertContent: dto.CertContent{
						CerificateBase64: base64.StdEncoding.EncodeToString([]byte(certResponse.Data["certificate"].(string))),
						PublicKeyBase64:  base64.StdEncoding.EncodeToString([]byte(pubKey)),
					},
					Subject: dto.Subject{
						C:  strings.Join(cert.Subject.Country, " "),
						ST: strings.Join(cert.Subject.Province, " "),
						L:  strings.Join(cert.Subject.Locality, " "),
						O:  strings.Join(cert.Subject.Organization, " "),
						OU: strings.Join(cert.Subject.OrganizationalUnit, " "),
						CN: cert.Subject.CommonName,
					},
					KeyMetadata: dto.PrivateKeyMetadataWithStregth{
						KeyType:     keyType.String(),
						KeyBits:     keyBits,
						KeyStrength: keyStrength,
					},
					ValidFrom: cert.NotBefore.String(),
					ValidTo:   cert.NotAfter.String(),
				})
			}
		}

	}
	return certs, nil

}

func (vs *VaultSecrets) DeleteCert(ctx context.Context, caType dto.CAType, caName string, serialNumber string) error {
	logger := ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)

	options := map[string]interface{}{
		"serial_number": serialNumber,
	}

	cert, err := vs.GetCert(ctx, caType, caName, serialNumber)
	if cert.Status == "revoked" {
		return &lamassuErrors.GenericError{
			Message:    "the certificate is already revoked",
			StatusCode: 412,
		}
	}

	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api POST /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/revoke serialnumber="+serialNumber, opentracing.ChildOf(parentSpan.Context()))

	_, err = vs.client.Logical().Write(vs.pkiPath+caType.ToVaultPath()+caName+"/revoke", options)
	span.Finish()
	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Could not revoke cert with serial number "+serialNumber+" from CA "+caName)
		err = errors.New("could not revoke cert from CA")
		return err
	}
	return nil
}

func (vs *VaultSecrets) hasEnrollerRole(ctx context.Context, caType dto.CAType, caName string) bool {
	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-ca-api: vault-api GET /v1/"+vs.pkiPath+caType.ToVaultPath()+caName+"/roles/enroller", opentracing.ChildOf(parentSpan.Context()))
	data, _ := vs.client.Logical().Read(vs.pkiPath + caType.ToVaultPath() + caName + "/roles/enroller")
	span.Finish()

	if data == nil {
		return false
	} else {
		return true
	}
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

func getPublicKeyInfo(cert x509.Certificate) (string, dto.KeyType, int, string) {
	key, _ := dto.ParseKeyType(cert.PublicKeyAlgorithm.String())
	var keyBits int
	switch key.String() {
	case "RSA":
		keyBits = cert.PublicKey.(*rsa.PublicKey).N.BitLen()
	case "EC":
		keyBits = cert.PublicKey.(*ecdsa.PublicKey).Params().BitSize
	}
	publicKeyDer, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))

	var keyStrength string = "unknown"
	switch key.String() {
	case "RSA":
		if keyBits < 2048 {
			keyStrength = "low"
		} else if keyBits >= 2048 && keyBits < 3072 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	case "EC":
		if keyBits <= 128 {
			keyStrength = "low"
		} else if keyBits > 128 && keyBits < 256 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	}

	return publicKeyPem, key, keyBits, keyStrength
}
