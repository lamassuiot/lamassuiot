package industrial

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	dmsDTO "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/test/e2e/utils"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"

	lamassudevice "github.com/lamassuiot/lamassuiot/pkg/device-manager/client"
)

var dmsName = "industrial-environment-dms"
var dmsCert = "./industrial-environment/dmsPer.crt"
var dmsKey = "./industrial-environment/dmsPer.key"
var deviceCert = "./industrial-environment/device.crt"
var deviceKey = "./industrial-environment/device.key"

func IndustrialEnvironment(caName string, deviceNumber int, reenroll int, certPath string, domain string) (string, error) {
	dmsClient, err := client.LamassuDmsClient(certPath, domain)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	devClient, err := client.LamassuDevClient(certPath, domain)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	key, dms, err := dmsClient.CreateDMSForm(context.Background(), dmsDTO.Subject{CN: dmsName}, dmsDTO.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dmsName)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	Privkey, _ := base64.StdEncoding.DecodeString(key)
	err = ioutil.WriteFile(dmsKey, Privkey, 0644)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	dms, err = dmsClient.UpdateDMSStatus(context.Background(), "APPROVED", dms.Id, []string{caName})
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	cert1, _ := base64.StdEncoding.DecodeString(dms.CerificateBase64)
	block, _ := pem.Decode([]byte(cert1))
	utils.InsertCert(dmsCert, block.Bytes)

	dev, err := CreateDevices(devClient, deviceNumber, caName, dms.Id, reenroll)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	err = devClient.DeleteDevice(context.Background(), dev.Id)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return dms.Id, nil
}

func CreateDevices(devClient lamassudevice.LamassuDevManagerClient, deviceNumber int, caName string, dmsId string, reenroll int) (dto.Device, error) {
	var dev dto.Device
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
		crt, err := devClient.Enroll(context.Background(), csr, caName, dmsCert, dmsKey, "/home/ikerlan/lamassu-compose-v2/tls-certificates/upstream/lamassu-device-manager/tls.crt", "dev-lamassu.zpd.ikerlan.es/api/devmanager")
		if err != nil {
			fmt.Println(err)
			return dto.Device{}, err
		}
		utils.InsertCert(deviceCert, crt.Cert.Raw)
		utils.InsertKey(deviceKey, Devicekey)
		for j := 0; j < reenroll; j++ {
			reenrollCert, err := devClient.Reenroll(context.Background(), csr, caName, deviceCert, deviceKey, "/home/ikerlan/lamassu-compose-v2/tls-certificates/upstream/lamassu-device-manager/tls.crt", "dev-lamassu.zpd.ikerlan.es/api/devmanager")
			if err != nil {
				fmt.Println(err)
				return dto.Device{}, err
			}
			utils.InsertCert(deviceCert, reenrollCert.Cert.Raw)
		}
		err = devClient.RevokeDeviceCert(context.Background(), dev.Id, "")
		if err != nil {
			fmt.Println(err)
			return dto.Device{}, err
		}
		serverKeyGen, err := devClient.ServerKeyGen(context.Background(), csr, caName, dmsCert, dmsKey, "/home/ikerlan/lamassu-compose-v2/tls-certificates/upstream/lamassu-device-manager/tls.crt", "dev-lamassu.zpd.ikerlan.es/api/devmanager")
		if err != nil {
			fmt.Println(err)
			return dto.Device{}, err
		}
		utils.InsertCert(deviceCert, serverKeyGen.Cert.Raw)
		utils.InsertKey(deviceKey, serverKeyGen.Key)
	}

	return dev, nil
}
