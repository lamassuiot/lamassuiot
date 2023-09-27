package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"lamassu-aws/pkg"
	"net/url"
	"os"

	"github.com/jakehl/goid"
	estClient "github.com/lamassuiot/lamassuiot/pkg/est/client"
	log "github.com/sirupsen/logrus"
)

const awsAccount = "a3penyvxwz0v8m-ats.iot.eu-west-1.amazonaws.com"

const estEnrollAPS = "ProductionDMS"
const estReenrollAPS = "DMS-Test"
const estEnroll = "jon.lamassu.zpd.ikerlan.es/api/dmsmanager"
const estReenroll = "dev.lamassu.zpd.ikerlan.es/api/devmanager"

const bootstrapCert = "/home/heimdal/lamassu-aws/bootstrap.crt"
const bootstrapKey = "/home/heimdal/lamassu-aws/bootstrap.key"

const deviceCert = "/home/heimdal/lamassu-aws/deviceAuthCA.crt"
const deviceKey = "/home/heimdal/lamassu-aws/deviceAuthCA.key"

func main() {
	// VerifyCerts()
	csr := Enroll()
	if csr == nil {
		return
	}
	// Reenroll(csr)
	// deviceCertKey, err := tls.LoadX509KeyPair(deviceCert, deviceKey)
	// if err != nil {
	// 	fmt.Println("Error loading device certificate and private key:", err)
	// 	return
	// }

	// deviceCert, err := x509.ParseCertificate(deviceCertKey.Certificate[0])
	// if err != nil {
	// 	fmt.Println("Error parsing device certificate:", err)
	// 	return
	// }
	// deviceID = deviceCert.Subject.CommonName

	// // Create a tls.Config with the device certificate and private key
	// tlsConfig := &tls.Config{
	// 	Certificates: []tls.Certificate{
	// 		{
	// 			Certificate: [][]byte{deviceCert.Raw},
	// 			PrivateKey:  deviceKey,
	// 		},
	// 	},
	// 	InsecureSkipVerify: true,
	// }

	// // Connect to AWS IoT Core using MQTT over TLS and the device certificate
	// opts := MQTT.NewClientOptions()
	// opts.AddBroker("tls://" + awsAccount + ":8883/mqtt")
	// opts.SetTLSConfig(tlsConfig)
	// opts.SetClientID(deviceID)

	// client := MQTT.NewClient(opts)
	// if token := client.Connect(); token.Wait() && token.Error() != nil {
	// 	time.Sleep(5 * time.Second)
	// 	if token := client.Connect(); token.Wait() && token.Error() != nil {
	// 		fmt.Println("Error connecting to AWS IoT Core:", token.Error())
	// 		return
	// 	}
	// }

	// log.Info("Device ", deviceID, " connected to AWS IoT Core")
}

func Enroll() *x509.CertificateRequest {
	log.Info("bootsraping device")

	//load bootstrap cert and key
	bootstrapCertKey, err := tls.LoadX509KeyPair(bootstrapCert, bootstrapKey)
	if err != nil {
		fmt.Println("Error loading bootstap certificate and private key:", err)
		return nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Panic("could not create RSA key: ", err)
		return nil
	}

	//device ID: random number
	deviceID := goid.NewV4UUID().String()
	// deviceID := "ba98d609-03e5-4a57-9802-1a33f3bf3856"
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: deviceID,
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil
	}

	bootstrapRSAPrivKey := bootstrapCertKey.PrivateKey.(*rsa.PrivateKey)
	_, err = x509.MarshalPKCS8PrivateKey(bootstrapRSAPrivKey)
	// bootstrapPemKey := pem.EncodeToMemory(
	// 	&pem.Block{
	// 		Type:  "PRIVATE KEY",
	// 		Bytes: bootstrapRSAPrivKeyBytes,
	// 	},
	// )
	var certs []*x509.Certificate
	for _, certificate := range bootstrapCertKey.Certificate {
		bootstrapCrt, _ := x509.ParseCertificate(certificate)
		certs = append(certs, bootstrapCrt)
	}

	enrollUrl, _ := url.Parse(estEnroll)
	enrollUrl.Host = "lamassu.zpd.ikerlan.es"
	enrollUrl.Path = "api/dmsmanager"

	//Identificar cual va a ser el path para hacer la llamada para hacer el enroll
	estEnrollClient, err := estClient.NewESTClient(nil, enrollUrl, certs[0], bootstrapRSAPrivKey, nil, true)
	if err != nil {
		log.Panic("Failed to create EST client: ", err)
	}

	deviceEnrollCrt, err := estEnrollClient.Enroll(context.Background(), estEnrollAPS, csr)
	if err != nil {
		log.Panic("failed the enroll process: ", err)
	}

	deviceCertSn := pkg.InsertNth(pkg.ToHexInt(deviceEnrollCrt.SerialNumber), 2)

	log.Info("enrolled new device ", deviceID, "with cert serial number: ", deviceCertSn)

	certFile, err := os.Create(deviceCert)
	if err != nil {
		return nil
	}

	certFile.Write(pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: deviceEnrollCrt.Raw,
		},
	))

	certFile.Close()

	keyFile, err := os.Create(deviceKey)
	if err != nil {
		return nil
	}

	deviceRSAPrivKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	devicePemKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: deviceRSAPrivKeyBytes,
		},
	)

	keyFile.Write(devicePemKey)
	keyFile.Close()
	return csr
}

/*
	func Reenroll(csr *x509.CertificateRequest) {
		log.Info("Reenroll device")
		//load bootstrap cert and key
		DeviceCertKey, err := tls.LoadX509KeyPair(deviceCert, deviceKey)
		if err != nil {
			fmt.Println("Error loading bootstap certificate and private key:", err)
			return
		}

		bootstrapRSAPrivKey := DeviceCertKey.PrivateKey.(*rsa.PrivateKey)
		bootstrapRSAPrivKeyBytes, _ := x509.MarshalPKCS8PrivateKey(bootstrapRSAPrivKey)
		devicePemKey := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: bootstrapRSAPrivKeyBytes,
			},
		)
		deviceCrt, _ := x509.ParseCertificate(DeviceCertKey.Certificate[0])
		enrollUrl, _ := url.Parse(estReenroll)
		estEnrollClient, err := estClient.NewESTClient(nil, enrollUrl, []*x509.Certificate{deviceCrt}, devicePemKey, nil, true)
		if err != nil {
			log.Panic("Failed to create EST client: ", err)
		}

		deviceReenrollCrt, err := estEnrollClient.Reenroll(context.Background(), csr, estReenrollAPS)
		if err != nil {
			log.Panic("failed the Reenroll process: ", err)
		}

		deviceCertSn := pkg.InsertNth(pkg.ToHexInt(deviceReenrollCrt.SerialNumber), 2)

		log.Info("Reenrolled device ", csr.Subject.CommonName, "with cert serial number: ", deviceCertSn)

		certFile, err := os.Create(deviceCert)
		if err != nil {
			return
		}

		certFile.Write(pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: deviceReenrollCrt.Raw,
			},
		))

		certFile.Close()
	}
*/
func VerifyCerts() {
	log.Info("bootsraping device")

	//load bootstrap cert and key
	bootstrapCertKey, _ := tls.LoadX509KeyPair(bootstrapCert, bootstrapKey)

	var certs []*x509.Certificate
	for _, certificate := range bootstrapCertKey.Certificate {
		bootstrapCrt, _ := x509.ParseCertificate(certificate)
		certs = append(certs, bootstrapCrt)
	}
	cCert, err := os.ReadFile("/home/heimdal/lamassu-aws/RootCa.crt")
	if err != nil {
		log.Fatal(err)
	}

	b, _ := pem.Decode(cCert)
	rootCA, err := x509.ParseCertificate(b.Bytes)

	err = verifyCertificate(certs[len(certs)-1], rootCA, false)
	if err != nil {
		log.Fatal(err)
	}
	verificationCACert := certs[len(certs)-1]
	for i := 2; i <= len(certs); i++ {
		fmt.Printf("clientCertificateChain[len(clientCertificateChain)-1].Subject.CommonName: %v\n", certs[len(certs)-i].Subject.CommonName)
		fmt.Printf("clientCertificateChain[len(clientCertificateChain)-1].Issuer.CommonName: %v\n", certs[len(certs)-i].Issuer.CommonName)
		fmt.Printf("verificationCACert.Subject.CommonName: %v\n", verificationCACert.Subject.CommonName)
		err = verifyCertificate(certs[len(certs)-i], verificationCACert, false)
		if err != nil {
			if err != nil {
				log.Fatal(err)
			}
		}
		verificationCACert = certs[len(certs)-i]
	}

}

func verifyCertificate(clientCertificate *x509.Certificate, caCertificate *x509.Certificate, allowExpiredRenewal bool) error {
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCertificate)

	opts := x509.VerifyOptions{
		Roots:     clientCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, err := clientCertificate.Verify(opts)
	if err != nil {

		return errors.New("could not verify client certificate: " + err.Error())

	}

	return nil
}
