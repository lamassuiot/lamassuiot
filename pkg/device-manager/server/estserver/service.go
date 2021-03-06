package estserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"reflect"
	"strconv"
	"time"

	"github.com/go-kit/kit/log"

	"github.com/go-kit/log/level"
	lamassuca "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	devicesModel "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device"
	devicesStore "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device/store"
	dmsStore "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/dms/store"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/utils"
	lamassuUtils "github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"

	esterror "github.com/lamassuiot/lamassuiot/pkg/est/server/api/errors"
	lamassuest "github.com/lamassuiot/lamassuiot/pkg/est/server/api/service"
)

type EstService struct {
	logger          log.Logger
	lamassuCaClient lamassuca.LamassuCaClient
	verifyUtils     utils.Utils
	devicesDb       devicesStore.DB
	dmsDb           dmsStore.DB
	minReenrollDays int
}

func NewEstService(lamassuCaClient *lamassuca.LamassuCaClient, verifyUtils *utils.Utils, devicesDb devicesStore.DB, dmsDb dmsStore.DB, minReenrollDays int, logger log.Logger) lamassuest.Service {

	return &EstService{
		lamassuCaClient: *lamassuCaClient,
		logger:          logger,
		verifyUtils:     *verifyUtils,
		devicesDb:       devicesDb,
		dmsDb:           dmsDb,
		minReenrollDays: minReenrollDays,
	}
}

type EstServiceI interface {
	Health(ctx context.Context) bool
	CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error)
	Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, cert *x509.Certificate) (*x509.Certificate, error)
	Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error)
	ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, cert *x509.Certificate) (*x509.Certificate, []byte, error)
}

func (s *EstService) Health(ctx context.Context) bool {
	return true
}

func (s *EstService) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	caType, _ := caDTO.ParseCAType("pki")
	var certs caDTO.GetCasResponse
	limit := 50
	i := 0
	for {
		cas, err := s.lamassuCaClient.GetCAs(ctx, caType, filters.QueryParameters{Pagination: filters.PaginationOptions{Limit: limit, Offset: i * limit}})
		if err != nil {
			return nil, err
		}
		if len(cas.CAs) == 0 {
			break
		}
		certs.CAs = append(certs.CAs, cas.CAs...)
		i++
	}

	x509Certificates := []*x509.Certificate{}
	for _, v := range certs.CAs {
		data, _ := base64.StdEncoding.DecodeString(v.CertContent.CerificateBase64)
		block, _ := pem.Decode([]byte(data))
		cert, _ := x509.ParseCertificate(block.Bytes)
		x509Certificates = append(x509Certificates, cert)
	}
	level.Debug(s.logger).Log("msg", "Certificates sent CACerts method")
	return x509Certificates, nil
}

func (s *EstService) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, clientCertificate *x509.Certificate) (*x509.Certificate, error) {
	var PrivateKeyMetadataWithStregth dto.PrivateKeyMetadataWithStregth
	var dmsDB dmsStore.DB
	deviceId := csr.Subject.CommonName
	sn := lamassuUtils.InsertNth(lamassuUtils.ToHexInt(clientCertificate.SerialNumber), 2)
	dmsId, err := s.dmsDb.SelectBySerialNumber(ctx, sn)
	if err != nil {
		return nil, err
	}
	aps, err = s.verifyCaName(ctx, aps, dmsDB, dmsId)
	if aps == "" {
		level.Debug(s.logger).Log("err", err, "msg", "Error DMS ID")
		authError := esterror.UnAuthorized{
			ResourceType: "DMS ID",
			ResourceId:   dmsId,
		}
		return &x509.Certificate{}, &authError
	}
	device, err := s.devicesDb.SelectDeviceById(ctx, deviceId)
	if err != nil {
		err = s.devicesDb.InsertDevice(ctx, csr.Subject.CommonName, csr.Subject.CommonName, dmsId, "", []string{}, "Cg/CgSmartphoneChip", "#0068D1")
		if err != nil {
			return nil, err
		}
		log := dto.DeviceLog{
			DeviceId:       csr.Subject.CommonName,
			LogMessage:     devicesModel.LogDeviceCreated.String(),
			LogDescription: "",
			LogType:        "INFO",
		}
		s.devicesDb.InsertLog(ctx, log)
		log = dto.DeviceLog{
			DeviceId:       csr.Subject.CommonName,
			LogMessage:     devicesModel.LogPendingProvision.String(),
			LogDescription: "",
			LogType:        "INFO",
		}
		s.devicesDb.InsertLog(ctx, log)
	}
	device, _ = s.devicesDb.SelectDeviceById(ctx, deviceId)
	if device.Status == devicesModel.DeviceDecommisioned.String() {
		return nil, errors.New("cant issue a certificate for a decommisioned device")
	}

	if device.Status == devicesModel.DeviceProvisioned.String() {
		return nil, errors.New("The device (" + deviceId + ") already has a valid certificate")
	}
	caType, err := caDTO.ParseCAType("pki")
	dataCert, _, err := s.lamassuCaClient.SignCertificateRequest(ctx, caType, aps, csr, true, csr.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	deviceId = dataCert.Subject.CommonName
	level.Debug(s.logger).Log("msg", csr.PublicKeyAlgorithm.String())
	switch csr.PublicKeyAlgorithm.String() {
	case "RSA":
		PrivateKeyMetadataWithStregth.KeyType = "RSA"
		rsaPublicKey := csr.PublicKey.(*rsa.PublicKey)
		PrivateKeyMetadataWithStregth.KeyBits = rsaPublicKey.Size() * 8
	case "ECDSA":
		PrivateKeyMetadataWithStregth.KeyType = "EC"
		ecPublicKey := csr.PublicKey.(*ecdsa.PublicKey)
		PrivateKeyMetadataWithStregth.KeyBits = ecPublicKey.Curve.Params().BitSize
	}
	PrivateKeyMetadataWithStregth.KeyStrength = getKeyStrength(PrivateKeyMetadataWithStregth.KeyType, PrivateKeyMetadataWithStregth.KeyBits)
	level.Debug(s.logger).Log("msg", PrivateKeyMetadataWithStregth)

	subject := dto.Subject{
		CommonName:       csr.Subject.CommonName,
		Organization:     s.verifyUtils.CheckIfNull(csr.Subject.Organization),
		OrganizationUnit: s.verifyUtils.CheckIfNull(csr.Subject.OrganizationalUnit),
		Country:          s.verifyUtils.CheckIfNull(csr.Subject.Country),
		State:            s.verifyUtils.CheckIfNull(csr.Subject.Province),
		Locality:         s.verifyUtils.CheckIfNull(csr.Subject.Locality),
	}
	err = s.devicesDb.SetKeyAndSubject(ctx, PrivateKeyMetadataWithStregth, subject, subject.CommonName)

	serialNumber := lamassuUtils.InsertNth(lamassuUtils.ToHexInt(dataCert.SerialNumber), 2)
	log := dto.DeviceLog{
		DeviceId:       deviceId,
		LogMessage:     devicesModel.LogProvisioned.String(),
		LogDescription: "The device has been provisioned through the enrollment process. The new certificate Serial Number is " + serialNumber,
		LogType:        "INFO",
	}
	s.devicesDb.InsertLog(ctx, log)
	log = dto.DeviceLog{
		DeviceId:       deviceId,
		LogMessage:     devicesModel.LogDeviceCertExpiration.String(),
		LogDescription: "Certificate with serial number " + serialNumber + " expires" + dataCert.NotAfter.String(),
		LogType:        "WARNMING",
	}
	s.devicesDb.InsertLog(ctx, log)

	certHistory := dto.DeviceCertHistory{
		SerialNumber: serialNumber,
		DeviceId:     deviceId,
		IsuuerName:   aps,
		Status:       devicesModel.CertHistoryActive.String(),
	}
	err = s.devicesDb.InsertDeviceCertHistory(ctx, certHistory)
	if err != nil {
		return nil, err
	}

	err = s.devicesDb.UpdateDeviceStatusByID(ctx, deviceId, devicesModel.DeviceProvisioned.String())
	if err != nil {
		return nil, err
	}

	err = s.devicesDb.UpdateDeviceCertificateSerialNumberByID(ctx, deviceId, serialNumber)
	if err != nil {
		return nil, err
	}

	level.Info(s.logger).Log("msg", "Certificate sent ENROLL method")
	return dataCert, nil
}

func (s *EstService) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	aps, err := s.verifyUtils.VerifyPeerCertificate(ctx, cert, false, nil)

	if err != nil {
		return nil, err
	}

	// Compare Subject fields
	if !reflect.DeepEqual(cert.Subject, csr.Subject) {
		return nil, err
	}

	deviceId := csr.Subject.CommonName
	device, err := s.devicesDb.SelectDeviceById(ctx, deviceId)
	if err != nil {
		return nil, err
	}
	if device.Status != devicesModel.DeviceProvisioned.String() {
		err := "Cant reenroll a device with status: " + device.Status
		return nil, errors.New(err)
	}
	currentCertHistory, err := s.devicesDb.SelectDeviceCertHistoryBySerialNumber(ctx, device.CurrentCertificate.SerialNumber)
	if err != nil {
		return nil, err
	}
	caType, err := caDTO.ParseCAType("pki")
	deviceCert, err := s.lamassuCaClient.GetCert(ctx, caType, currentCertHistory.IsuuerName, currentCertHistory.SerialNumber)

	if err != nil {
		return nil, err
	}

	certExpirationTime, err := time.Parse("2006-01-02 15:04:05 -0700 MST", deviceCert.ValidTo)
	if err != nil {
		errMsg := "Could not parse the device's cert expiration time"
		level.Debug(s.logger).Log("err", err, "msg", errMsg)
		return nil, err
	}
	if certExpirationTime.Before(time.Now().Add(time.Hour * 24 * time.Duration(s.minReenrollDays))) {

	} else {
		msg := "Cant reenroll a provisioned device before " + strconv.Itoa(s.minReenrollDays) + " days of its expiration time"
		return nil, errors.New(msg)
	}

	serialNumberToRevoke := currentCertHistory.SerialNumber

	err = s.lamassuCaClient.RevokeCert(ctx, caType, currentCertHistory.IsuuerName, serialNumberToRevoke)
	if err != nil {
		errMsg := "An error ocurred while revoking the current device's cert"
		level.Error(s.logger).Log("err", err, "msg", errMsg)
		return nil, err
	}
	log := dto.DeviceLog{
		DeviceId:       deviceId,
		LogMessage:     devicesModel.LogCertRevoked.String(),
		LogDescription: "Certificate with serial number " + serialNumberToRevoke + " has been revoked",
		LogType:        "CRITICAL",
	}
	s.devicesDb.InsertLog(ctx, log)
	err = s.devicesDb.UpdateDeviceStatusByID(ctx, deviceId, devicesModel.DeviceCertRevoked.String())
	if err != nil {
		return nil, err
	}

	err = s.devicesDb.UpdateDeviceCertificateSerialNumberByID(ctx, deviceId, "")
	if err != nil {
		return nil, err
	}

	dataCert, _, err := s.lamassuCaClient.SignCertificateRequest(ctx, caType, aps, csr, true, csr.Subject.CommonName)

	deviceId = dataCert.Subject.CommonName
	serialNumber := lamassuUtils.InsertNth(lamassuUtils.ToHexInt(dataCert.SerialNumber), 2)
	log = dto.DeviceLog{
		DeviceId:       deviceId,
		LogMessage:     devicesModel.LogDeviceReenroll.String(),
		LogDescription: "The device has been provisioned through the reenrollment process. The new certificate Serial Number is " + serialNumber,
		LogType:        "SUCCESS",
	}
	s.devicesDb.InsertLog(ctx, log)
	log = dto.DeviceLog{
		DeviceId:       deviceId,
		LogMessage:     devicesModel.LogDeviceCertExpiration.String(),
		LogDescription: "Certificate with serial number " + serialNumber + " expires" + dataCert.NotAfter.String(),
		LogType:        "WARNMING",
	}

	certHistory := dto.DeviceCertHistory{
		SerialNumber: serialNumber,
		DeviceId:     deviceId,
		IsuuerName:   aps,
		Status:       devicesModel.CertHistoryActive.String(),
	}
	err = s.devicesDb.InsertDeviceCertHistory(ctx, certHistory)
	if err != nil {
		return nil, err
	}

	err = s.devicesDb.UpdateDeviceStatusByID(ctx, deviceId, devicesModel.DeviceProvisioned.String())

	err = s.devicesDb.UpdateDeviceCertificateSerialNumberByID(ctx, deviceId, serialNumber)

	level.Info(s.logger).Log("msg", "Certificate sent REENROLL method")
	return dataCert, nil
}
func (s *EstService) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, cert *x509.Certificate) (*x509.Certificate, []byte, error) {
	csrkey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	privkey, err := x509.MarshalPKCS8PrivateKey(csrkey)

	csr, err = s.verifyUtils.GenerateCSR(csr, csrkey)

	crt, err := s.Enroll(ctx, csr, aps, cert)
	if err != nil {
		return nil, nil, err
	}
	return crt, privkey, nil
}
func getKeyStrength(keyType string, keyBits int) string {
	var keyStrength string = "unknown"
	switch keyType {
	case "RSA":
		if keyBits < 2048 {
			keyStrength = "low"
		} else if keyBits >= 2048 && keyBits < 3072 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	case "EC":
		if keyBits < 224 {
			keyStrength = "low"
		} else if keyBits >= 224 && keyBits < 256 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	}
	return keyStrength
}

func (s *EstService) verifyCaName(ctx context.Context, caname string, dmsDB dmsStore.DB, dmsid string) (string, error) {
	dmsCas, err := s.dmsDb.SelectByDMSIDAuthorizedCAs(ctx, dmsid)
	if err != nil {
		return "", err
	}
	for _, dmsCa := range dmsCas {
		if caname == dmsCa.CaName {
			return caname, nil
		}
	}
	return "", nil
}
