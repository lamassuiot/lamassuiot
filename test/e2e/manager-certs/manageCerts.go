package certs

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	lamassuCAClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	lamassudevice "github.com/lamassuiot/lamassuiot/pkg/device-manager/client"
	"github.com/lamassuiot/lamassuiot/test/e2e/utils"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"
)

var dmsCert = "/home/ikerlan/lamassu/lamassuiot/test/e2e/industrial_environment/dmsPer.crt"
var dmsKey = "/home/ikerlan/lamassu/lamassuiot/test/e2e/industrial_environment/dmsPer.key"

func ManageCerts(caName string, scaleIndex int) error {
	var f, _ = os.Create("./GetIssuedCerts_" + strconv.Itoa(scaleIndex) + ".csv")
	var f1, _ = os.Create("./GetCaCerts_" + strconv.Itoa(scaleIndex) + ".csv")
	caClient, err := client.LamassuCaClient()
	if err != nil {
		fmt.Println(err)
		return err
	}
	devClient, err := client.LamassuDevClient()
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = LatencyGetCACerts(devClient, caName, f1)
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = LatencyIssuedCerts(caClient, caName, f)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}

func LatencyGetCACerts(devClient lamassudevice.LamassuDevManagerClient, caName string, f *os.File) error {
	var max, min float64
	max = 0
	min = 12
	var totalCerts int
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		certs, err := devClient.CACerts(context.Background(), caName, dmsCert, dmsKey, "/home/ikerlan/lamassu-compose-v2/tls-certificates/upstream/lamassu-device-manager/tls.crt", "dev-lamassu.zpd.ikerlan.es/api/devmanager")
		if err != nil {
			fmt.Println(err)
			return err
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		totalCerts = len(certs)
	}
	media := (max + min) / 2
	err := utils.WriteDataFile(string(totalCerts), max, min, media, f)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}

func LatencyIssuedCerts(caClient lamassuCAClient.LamassuCaClient, caName string, f *os.File) error {
	var max, min float64
	max = 0
	min = 12
	var totalCerts int
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		certs, err := caClient.GetIssuedCerts(context.Background(), caDTO.Pki, caName, "{1,15}")
		if err != nil {
			fmt.Println(err)
			return err
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		totalCerts = certs.TotalCerts
	}
	media := (max + min) / 2
	err := utils.WriteDataFile(string(totalCerts), max, min, media, f)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}
