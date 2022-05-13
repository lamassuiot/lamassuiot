package cas

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/globalsign/pemfile"
	"github.com/jakehl/goid"
	lamassuCAClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"

	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/test/e2e/utils"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"
)

var importcaCert = "/home/ikerlan/lamassu/lamassuiot/test/e2e/manage-cas/importca.crt"
var importcaKey = "/home/ikerlan/lamassu/lamassuiot/test/e2e/manage-cas/importca.key"

func ManageCAs(caNumber int, scaleIndex int) (caDTO.Cert, error) {
	var f, _ = os.Create("./GetCAs_" + strconv.Itoa(scaleIndex) + ".csv")

	caClient, err := client.LamassuCaClient()
	if err != nil {
		return caDTO.Cert{}, err
	}
	var createCa []caDTO.Cert
	for i := 0; i < caNumber; i++ {
		caName := goid.NewV4UUID().String()

		_, err = caClient.CreateCA(context.Background(), caDTO.Pki, caName, caDTO.PrivateKeyMetadata{KeyType: "rsa", KeyBits: 2048}, caDTO.Subject{CN: caName}, 365*time.Hour, 30*time.Hour)
		if err != nil {
			fmt.Println(err)
			return caDTO.Cert{}, err
		}
		createCa, err = LatencyGetCAs(caClient, f)
		if err != nil {
			return caDTO.Cert{}, err
		}

	}
	err = caClient.DeleteCA(context.Background(), caDTO.Pki, createCa[caNumber-1].Name)
	if err != nil {
		return caDTO.Cert{}, err
	}

	certContent, err := ioutil.ReadFile(importcaCert)
	cpb, _ := pem.Decode(certContent)
	importcrt, err := x509.ParseCertificate(cpb.Bytes)
	privateKey, err := pemfile.ReadPrivateKey(importcaKey)

	ca, err := caClient.ImportCA(context.Background(), caDTO.Pki, importcrt.Subject.CommonName, *importcrt, caDTO.PrivateKey{KeyType: caDTO.RSA, Key: privateKey}, 30*time.Hour)
	if err != nil {
		fmt.Println(err)
		return caDTO.Cert{}, err
	}

	return ca, nil
}

func LatencyGetCAs(caClient lamassuCAClient.LamassuCaClient, f *os.File) ([]caDTO.Cert, error) {
	var max, min float64
	max = 0
	min = 12
	var createCa []caDTO.Cert
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		cas, err := caClient.GetCAs(context.Background(), caDTO.Pki)
		if err != nil {
			fmt.Println(err)
			return []caDTO.Cert{}, err
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		createCa = cas
	}
	media := (max + min) / 2
	err := utils.WriteDataFile(string(len(createCa)), max, min, media, f)
	if err != nil {
		fmt.Println(err)
		return []caDTO.Cert{}, err
	}

	return createCa, nil
}
