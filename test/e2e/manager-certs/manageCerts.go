package certs

import (
	"context"
	"crypto/x509"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	lamassuCAClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	lamassudevice "github.com/lamassuiot/lamassuiot/pkg/device-manager/client"
	"github.com/lamassuiot/lamassuiot/test/e2e/utils"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"
)

var dmsCertFile = "./test/e2e/industrial-environment/dmsPer.crt"
var dmsKeyFile = "./test/e2e/industrial-environment/dmsPer.key"

func ManageCerts(caName string, scaleIndex int, certPath string, domain string) error {
	var logger log.Logger
	logger = log.NewJSONLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	var f, _ = os.Create("./test/e2e/manager-certs/GetIssuedCerts_" + strconv.Itoa(scaleIndex) + ".csv")
	var f1, _ = os.Create("./test/e2e/manager-certs/GetCaCerts_" + strconv.Itoa(scaleIndex) + ".csv")
	caClient, err := client.LamassuCaClient(certPath, domain)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	devClient, err := client.LamassuDevClient(certPath, domain)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}

	serverCert, err := utils.ReadCertPool(certPath)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	dmsCert, err := utils.ReadCert(dmsCertFile)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	dmsKey, err := utils.ReadKey(dmsKeyFile)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	err = LatencyGetCACerts(devClient, caName, f1, domain, dmsCert, dmsKey, serverCert)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}

	err = LatencyIssuedCerts(caClient, caName, f)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	f.Close()
	f1.Close()
	return nil
}

func LatencyGetCACerts(devClient lamassudevice.LamassuDeviceManagerClient, caName string, f *os.File, domain string, clientCert *x509.Certificate, clientKey []byte, serverCert *x509.CertPool) error {
	var max, min float64
	max = 0
	min = 12
	var totalCerts int
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		certs, err := devClient.CACerts(context.Background(), caName, clientCert, clientKey, serverCert, domain+"/api/devmanager")
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
	err := utils.WriteDataFile(strconv.Itoa(totalCerts), max, min, media, f)
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
	err := utils.WriteDataFile(strconv.Itoa(totalCerts), max, min, media, f)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}
