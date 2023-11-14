package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"

	"github.com/haritzsaiz/est"
	"github.com/kuzemkon/aws-iot-device-sdk-go/device"
)

const p = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iot:*\"],\"Resource\":[\"*\"]}]}"
const awsIotCA = `-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy
rqXRfboQnoZsG4q5WTP468SQvvG5
-----END CERTIFICATE-----`

func main() {
	caDur := models.TimeDuration(time.Hour * 25)
	caIss := models.TimeDuration(time.Minute * 3)
	caClient := clients.NewHttpCAClient(http.DefaultClient, "http://localhost:8443/api/ca")
	testEnrollmentCA, err := caClient.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:            models.Subject{CommonName: "ShortTTLV2"},
		CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDur},
		IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
		Metadata: map[string]any{
			"lamassu.io/iot/aws.954121426360": models.IoTAWSCAMetadata{
				Register: true,
			},
		},
		ID: "Root",
	})
	chk(err)

	fmt.Println("=============================")
	fmt.Println("CN:" + testEnrollmentCA.Subject.CommonName)
	fmt.Println("ID:" + testEnrollmentCA.ID)
	fmt.Println("SN:" + testEnrollmentCA.SerialNumber)
	fmt.Println("=============================")

	childCALvl1, err := caClient.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:            models.Subject{CommonName: "CA Lvl 1"},
		CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDur},
		IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
		ParentID:           testEnrollmentCA.ID,
		EngineID:           "dockertest-localstack-smngr",
		ID:                 "Lvl1",
	})
	chk(err)

	fmt.Println("=============================")
	fmt.Println("CN:" + childCALvl1.Subject.CommonName)
	fmt.Println("ID:" + childCALvl1.ID)
	fmt.Println("SN:" + childCALvl1.SerialNumber)
	fmt.Println("=============================")

	childCALvl2, err := caClient.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:            models.Subject{CommonName: "CA Lvl 2"},
		CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDur},
		IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
		ParentID:           childCALvl1.ID,
		EngineID:           "golang-1",
		ID:                 "Lvl2",
	})
	chk(err)

	fmt.Println(childCALvl2.ID)

	testBootCA, err := caClient.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:            models.Subject{CommonName: "testBootCA"},
		CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDur},
		IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
	})
	chk(err)

	dmsClient := clients.NewHttpDMSManagerClient(http.DefaultClient, "http://localhost:8443/api/dmsmanager")
	dms, err := dmsClient.CreateDMS(context.Background(), services.CreateDMSInput{
		ID:   fmt.Sprintf("my-dms-%d", time.Now().Unix()),
		Name: "My DMS",
		Metadata: map[string]any{
			"lamassu.io/iot/aws.954121426360": models.IotAWSDMSMetadata{
				RegistrationMode: models.AutomaticAWSIoTRegistrationMode,
				JITPProvisioningTemplate: struct {
					ARN                 string "json:\"arn,omitempty\""
					AWSCACertificateId  string "json:\"aws_ca_id,omitempty\""
					ProvisioningRoleArn string "json:\"provisioning_role_arn\""
					EnableTemplate      bool   "json:\"enable_template\""
				}{
					ProvisioningRoleArn: "",
					EnableTemplate:      false,
				},
				GroupNames: []string{"TEST-LMS"},
				Policies: []models.AWSIoTPolicy{
					models.AWSIoTPolicy{PolicyName: "my-p", PolicyDocument: p},
				},
				ShadowConfig: struct {
					Enable     bool   "json:\"enable\""
					ShadowName string "json:\"shadow_name,omitempty\""
				}{
					Enable:     true,
					ShadowName: "",
				},
			},
		},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
				EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
					AuthMode: models.ESTAuthModeClientCertificate,
					AuthOptionsMTLS: models.AuthOptionsClientCertificate{
						ValidationCAs:        []string{testBootCA.ID},
						ChainLevelValidation: -1,
					},
				},
				DeviceProvisionProfile: models.DeviceProvisionProfile{
					Icon:      "BiSolidCreditCardFront",
					IconColor: "#25ee32-#222222",
					Metadata:  map[string]any{},
					Tags:      []string{"iot", "testdms", "cloud"},
				},
				EnrollmentCA:                testEnrollmentCA.ID,
				RegistrationMode:            models.JITP,
				EnableReplaceableEnrollment: true,
			},
			ReEnrollmentSettings: models.ReEnrollmentSettings{
				AdditionalValidationCAs:     []string{},
				ReEnrollmentDelta:           models.TimeDuration(time.Hour),
				EnableExpiredRenewal:        true,
				PreventiveReEnrollmentDelta: models.TimeDuration(time.Minute * 2),
				CriticalReEnrollmentDelta:   models.TimeDuration(time.Minute * 1),
			},
			CADistributionSettings: models.CADistributionSettings{
				IncludeLamassuSystemCA: true,
				IncludeEnrollmentCA:    true,
				ManagedCAs:             []string{},
			},
		},
	})
	chk(err)

	fmt.Println(dms.ID)

	bootKey, err := helpers.GenerateRSAKey(2048)
	chk(err)

	deviceCsr, err := helpers.GenerateCertificateRequest(models.Subject{CommonName: "device-3"}, bootKey)
	chk(err)

	sigedCrt, err := caClient.SignCertificate(context.Background(), services.SignCertificateInput{
		CAID:         testBootCA.ID,
		CertRequest:  (*models.X509CertificateRequest)(deviceCsr),
		SignVerbatim: true,
	})
	chk(err)

	fmt.Println(sigedCrt.SerialNumber)

	pem, err := base64.StdEncoding.DecodeString(sigedCrt.Certificate.String())
	chk(err)
	urlEncodedCrt := url.QueryEscape(string(pem))

	estHttpCli := est.NewHttpClient(est.HttpClientBuilder{
		PrivateKey:   bootKey,
		Certificates: []*x509.Certificate{(*x509.Certificate)(sigedCrt.Certificate)},
	})

	estCli := est.Client{
		HttpClient:            estHttpCli,
		HttpProtocol:          "http",
		AdditionalPathSegment: dms.ID,
		Host:                  "localhost:8443/api/dmsmanager",
		AdditionalHeaders: map[string]string{
			"x-forwarded-client-cert": fmt.Sprintf("Cert=%s", urlEncodedCrt),
		},
	}

	time.Sleep(time.Second * 3)

	fmt.Println("first enroll")
	crt, err := estCli.Enroll(context.Background(), deviceCsr)
	chk(err)

	time.Sleep(time.Second * 3)
	fmt.Println("second enroll")
	crt, err = estCli.Enroll(context.Background(), deviceCsr)
	chk(err)

	fmt.Println(crt.SerialNumber)
	fmt.Println(crt.Subject.CommonName)
	fmt.Println(crt.Issuer.CommonName)

	urlEncodedCrt = url.QueryEscape(string(helpers.CertificateToPEM(crt)))
	estCli.AdditionalHeaders = map[string]string{
		"x-forwarded-client-cert": fmt.Sprintf("Cert=%s", urlEncodedCrt),
	}

	fmt.Println("first ReEnroll")
	crt, err = estCli.Reenroll(context.Background(), deviceCsr)
	chk(err)

	time.Sleep(time.Second * 3)

	fmt.Println("second ReEnroll")
	crt, err = estCli.Reenroll(context.Background(), deviceCsr)
	chk(err)

	keystr, err := helpers.PrivateKeyToPEM(bootKey)
	chk(err)

	err = os.WriteFile("device.key", []byte(keystr), 0644)
	chk(err)
	err = os.WriteFile("device.crt", []byte(helpers.CertificateToPEM(crt)), 0644)
	chk(err)
	err = os.WriteFile("aws.crt", []byte(awsIotCA), 0644)
	chk(err)

	time.Sleep(time.Second * 3)

	thing, err := device.NewThing(
		device.KeyPair{
			PrivateKeyPath:    "device.key",
			CertificatePath:   "device.crt",
			CACertificatePath: "aws.crt",
		},
		"a3penyvxwz0v8m-ats.iot.eu-west-1.amazonaws.com", // AWS IoT endpoint
		device.ThingName(sigedCrt.Subject.CommonName),
	)
	chk(err)

	s, err := thing.GetThingShadow()
	chk(err)

	fmt.Println(s)

	shadowChan, shadowErr, err := thing.SubscribeForThingShadowChanges()
	chk(err)

	for {
		select {
		case s, ok := <-shadowChan:
			if !ok {
				panic("failed to read from shadow channel")
			}
			fmt.Println(s)
		case s, ok := <-shadowErr:
			if !ok {
				panic("failed to read from shadow err channel")
			}
			fmt.Println(s)
		}
	}

}

func chk(err error) {
	if err != nil {
		panic(err)
	}
}
