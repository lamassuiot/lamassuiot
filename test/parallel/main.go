package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jakehl/goid"
	lamassudevice "github.com/lamassuiot/lamassuiot/pkg/device-manager/client"
	dmsDTO "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/test/e2e/utils"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"
)

var domain = flag.String("domain", "", "domain")
var cacert = flag.String("cert", "", "ca certificate")
var workToDo = flag.Int("enroll", 10000, "enroll counter")
var maxGoroutines = flag.Int("maxroutines", 10, "maxGoroutines")

var counter uint64 = 0
var errCounter uint64 = 0
var relativePercentage uint64 = uint64(*workToDo) / 100
var t0 = time.Now()

func work(id int, caName string, deviceManagerClient *lamassudevice.LamassuDeviceManagerClient, caCertPool *x509.CertPool, dmsCert *x509.Certificate, dmsKey []byte, deviceKey *rsa.PrivateKey) {
	// defer wg.Done()
	// t0 := time.Now()

	cli := *deviceManagerClient

	// t0rand := time.Now()
	devID := goid.NewV4UUID().String()
	csr, _ := utils.GenerateCSR(deviceKey, "rsa", devID)
	// t1rand := time.Now()

	// t0enroll := time.Now()
	_, err := cli.Enroll(context.Background(), csr, caName, dmsCert, dmsKey, caCertPool, *domain+"/api/devmanager")
	// atomic.AddUint64(&counter, 1)
	counter = counter + 1
	if err != nil {
		fmt.Println(err)
		// atomic.AddUint64(&errCounter, 1)
		errCounter = errCounter + 1
	}

	t1 := time.Now()
	if counter%relativePercentage == 0 {
		fmt.Println(counter/relativePercentage, errCounter, t1.Sub(t0).Seconds())
	}
}

func main() {
	flag.Parse()
	if *domain == "" || *cacert == "" {
		return
	}

	guard := make(chan struct{}, *maxGoroutines)

	dmsClient, _ := client.LamassuDmsClient(*cacert, *domain)
	devManager, _ := client.LamassuDevClient(*cacert, *domain)

	dmsName := "concurrency-" + goid.NewV4UUID().String()
	fmt.Println(dmsName)
	key, dms, _ := dmsClient.CreateDMSForm(context.Background(), dmsDTO.Subject{CN: dmsName}, dmsDTO.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dmsName)
	dms, _ = dmsClient.UpdateDMSStatus(context.Background(), "APPROVED", dms.Id, []string{"test-concurrency"})

	privateKey, _ := base64.StdEncoding.DecodeString(key)
	f, _ := os.Create("dms.key")
	f.Write(privateKey)
	f.Close()

	f, _ = os.Create("dms.crt")
	cert, _ := base64.StdEncoding.DecodeString(dms.CerificateBase64)
	f.Write(cert)
	f.Close()

	caCertPool, _ := utils.ReadCertPool(*cacert)
	dmsCert, _ := utils.ReadCert("dms.crt")
	dmsKey, _ := utils.ReadKey("dms.key")

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	for i := 0; i < *workToDo; i++ {
		guard <- struct{}{} // would block if guard channel is already filled
		go func(n int) {
			work(i, "test-concurrency", &devManager, caCertPool, dmsCert, dmsKey, rsaKey)
			<-guard
		}(i)
	}

	fmt.Println("Waiting for goroutines to finish...")
	// wg.Wait()

	t1 := time.Now()

	fmt.Println(counter)
	fmt.Printf("Done in %f seconds!\n", t1.Sub(t0).Seconds())
}
