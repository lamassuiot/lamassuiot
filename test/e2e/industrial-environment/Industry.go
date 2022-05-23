package industrial

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	dmsDTO "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/test/e2e/utils"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"

	lamassudevice "github.com/lamassuiot/lamassuiot/pkg/device-manager/client"
)

var dmsName = "industrial-environment-dms"
var dmsCertFile = "./test/e2e/industrial-environment/dmsPer.crt"
var dmsKeyFile = "./test/e2e/industrial-environment/dmsPer.key"
var deviceCertFile = "./test/e2e/industrial-environment/device.crt"
var deviceKeyFile = "./test/e2e/industrial-environment/device.key"

func IndustrialEnvironment(caName string, deviceNumber int, reenroll int, certPath string, domain string) (string, error) {
	var logger log.Logger
	logger = log.NewJSONLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	dmsClient, err := client.LamassuDmsClient(certPath, domain)
	if err != nil {
		level.Error(logger).Log("err", err)
		return "", err
	}
	devClient, err := client.LamassuDevClient(certPath, domain)
	if err != nil {
		level.Error(logger).Log("err", err)
		return "", err
	}
	key, dms, err := dmsClient.CreateDMSForm(context.Background(), dmsDTO.Subject{CN: dmsName}, dmsDTO.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dmsName)
	if err != nil {
		level.Error(logger).Log("err", err)
		return "", err
	}
	Privkey, _ := base64.StdEncoding.DecodeString(key)
	f, _ := os.Create(dmsKeyFile)
	f.Write(Privkey)
	f.Close()

	dms, err = dmsClient.UpdateDMSStatus(context.Background(), "APPROVED", dms.Id, []string{caName})
	if err != nil {
		level.Error(logger).Log("err", err)
		return "", err
	}
	cert1, _ := base64.StdEncoding.DecodeString(dms.CerificateBase64)
	block, _ := pem.Decode([]byte(cert1))
	utils.InsertCert(dmsCertFile, block.Bytes)

	serverCert, err := utils.ReadCertPool(certPath)
	if err != nil {
		level.Error(logger).Log("err", err)
		return "", err
	}
	dmsCert, err := utils.ReadCert(dmsCertFile)
	if err != nil {
		level.Error(logger).Log("err", err)
		return "", err
	}
	dmsKey, err := utils.ReadKey(dmsKeyFile)
	if err != nil {
		level.Error(logger).Log("err", err)
		return "", err
	}

	dev, err := CreateDevices(devClient, deviceNumber, caName, dms.Id, reenroll, domain, dmsCert, dmsKey, serverCert)
	if err != nil {
		level.Error(logger).Log("err", err)
		return "", err
	}

	err = devClient.DeleteDevice(context.Background(), dev.Id)
	if err != nil {
		level.Error(logger).Log("err", err)
		return "", err
	}
	return dms.Id, nil
}

func CreateDevices(devClient lamassudevice.LamassuDeviceManagerClient, deviceNumber int, caName string, dmsId string, reenroll int, domain string, clientCert *x509.Certificate, clientKey []byte, serverCert *x509.CertPool) (dto.Device, error) {
	var dev dto.Device
	var crt dto.Enroll
	for i := 0; i < deviceNumber; i++ {
		dev, err := devClient.CreateDevice(context.Background(), "test-dev", goid.NewV4UUID().String(), dmsId, "descripcion", []string{}, "", "")
		if err != nil {
			fmt.Println(err)
			return dto.Device{}, err
		}
		dev, err = devClient.UpdateDeviceById(context.Background(), "", dev.Id, dmsId, "updated device", []string{}, "", "")
		if err != nil {
			fmt.Println(err)
			return dto.Device{}, err
		}
		Devicekey, csr, err := utils.GenrateRandKey(dev.Id)
		if err != nil {
			fmt.Println(err)
			return dto.Device{}, err
		}
		crt, err = devClient.Enroll(context.Background(), csr, caName, clientCert, clientKey, serverCert, domain+"/api/devmanager")
		if err != nil {
			fmt.Println(err)
			return dto.Device{}, err
		}
		utils.InsertCert(deviceCertFile, crt.Cert.Raw)
		utils.InsertKey(deviceKeyFile, Devicekey)
		deviceKey, err := utils.ReadKey(deviceCertFile)
		if err != nil {
			fmt.Println(err)
			return dto.Device{}, err
		}
		for j := 0; j < reenroll; j++ {
			crt, err = devClient.Reenroll(context.Background(), csr, caName, crt.Cert, deviceKey, serverCert, domain+"/api/devmanager")
			if err != nil {
				fmt.Println(err)
				return dto.Device{}, err
			}
			utils.InsertCert(deviceCertFile, crt.Cert.Raw)
		}
		err = devClient.RevokeDeviceCert(context.Background(), dev.Id, "")
		if err != nil {
			fmt.Println(err)
			return dto.Device{}, err
		}
		serverKeyGen, err := devClient.ServerKeyGen(context.Background(), csr, caName, clientCert, clientKey, serverCert, domain+"/api/devmanager")
		if err != nil {
			fmt.Println(err)
			return dto.Device{}, err
		}
		utils.InsertCert(deviceCertFile, serverKeyGen.Cert.Raw)
		utils.InsertKey(deviceKeyFile, serverKeyGen.Key)
	}

	return dev, nil
}
