package e2e

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/globalsign/est"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	cmodels "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
)

type UseCase1Input struct {
	LamassuHostname    string
	LamassuPort        int
	LamassuHTTProtocol string
	DeviceIDPrefix     string
	DMSPrefix          string
	AwsAccountID       string
	AwsIotCoreEndpoint string
	AwsShadowName      string
}

func RunUseCase1(input UseCase1Input) error {
	lUsecase := helpers.SetupLogger(cconfig.Info, "Test Case", "test")

	var hostname = input.LamassuHostname
	var port = input.LamassuPort
	var protocol = input.LamassuHTTProtocol
	var devicePrefix = input.DeviceIDPrefix
	var awsIotCoreEndpoint = input.AwsIotCoreEndpoint
	//var awsNamedShadowName = input.AwsShadowName
	var awsAccountID = input.AwsAccountID

	const p = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iot:*\"],\"Resource\":[\"*\"]}]}"

	deviceID := fmt.Sprintf("%s%d", devicePrefix, time.Now().Unix())
	dmsID := fmt.Sprintf("%s%d", input.DMSPrefix, time.Now().Unix())

	//1. Create Out-of-band CA1 (ca expiration of 1h)
	//2. Import CA1 into lamassu (priv key + crt) (default CE) (issuance expiration: 5m)
	//3. Create CA2 in Lamassu (Try engine different from default CE. If not possible, use default CE)
	//4. Sync CA1 with AWS
	//5. Create DMS with enrollment CA1 and validation CA2. Add CA1 in CACerts. Enable AWS Sync (RegMode: Auto)
	//6. Sign Bootstrap Cert with CA2
	//7. Device Flows:
	//7.1	Device 1:
	//7.1.1		Enroll with Lamassu
	//7.1.2		Connect to AWS IoT Core
	//7.1.3		Wait 5 seconds and FORCE Reenroll via AWS Shadow
	//7.1.4		ReEnroll on shadow Update
	//7.1.5		Disconnect and ReConnect to AWS IoT Core
	//7.2	Device 2:
	//7.2.1		Enroll OFFLINE (Out-of-band)
	//7.2.2		Import Certificate to Lamassu
	//7.2.3		Connect to AWS IoT Core
	//7.2.4		Wait 5 seconds and FORCE CACerts via AWS Shadow
	//7.2.5		CACerts on shadow Update
	//7.2.6		Check CACerts
	//8. Decommission Device 1
	//9. Try Disconnecting and ReConnecting to AWS IoT Core with Device 1
	//10. Get OCSP Response for Last Active Certificate for Device 1 using CA1 and Check Revocation Reason
	//11. Get CRL for CA1 and Check Revocation Reason

	//Initialization of the client to connect to monolithic

	log := helpers.SetupLogger(cconfig.Info, "Test Case", "httpClient")

	httpCli, err := sdk.BuildHTTPClient(cconfig.HTTPClient{
		AuthMode: cconfig.NoAuth,
		HTTPConnection: cconfig.HTTPConnection{
			Protocol: cconfig.HTTPS,
			BasicConnection: cconfig.BasicConnection{
				TLSConfig: cconfig.TLSConfig{
					InsecureSkipVerify: true,
				},
			},
		},
	}, log)
	if err != nil {
		return err
	}

	caClient := sdk.NewHttpCAClient(httpCli, fmt.Sprintf("%s://%s:%d/api/ca", protocol, hostname, port))
	dmsClient := sdk.NewHttpDMSManagerClient(httpCli, fmt.Sprintf("%s://%s:%d/api/dmsmanager", protocol, hostname, port))

	//1. Create Out-of-band CA1 (ca expiration of 1h
	log.Infof("1. Create Out-of-band CA1 (ca expiration of 1h)")
	lUsecase.WithField("", "Step 1").Info("starting")
	caExp := (time.Hour * 1)
	cert1, key1, err := chelpers.GenerateSelfSignedCA(x509.RSA, caExp, "MyCA")

	if err != nil {
		return err
	}

	//2. Import CA1 into lamassu (priv key + crt) (default CE) (issuance expiration: 5m)
	log.Infof("2. Import CA1 into lamassu (priv key + crt) (default CE) (issuance expiration: 5m)")
	ca2Iss := models.TimeDuration(time.Minute * 5)
	ca1, err := caClient.ImportCA(context.Background(), services.ImportCAInput{
		CAType: models.CertificateTypeImportedWithKey,
		IssuanceExpiration: models.Expiration{
			Type:     models.Duration,
			Duration: (*models.TimeDuration)(&ca2Iss),
		},
		CACertificate: (*models.X509Certificate)(cert1),
		KeyType:       cmodels.KeyType(x509.RSA),
		CARSAKey:      key1.(*rsa.PrivateKey),
	})
	if err != nil {
		return err
	}

	//3. Create CA2 in Lamassu (Try engine different from default CE. If not possible, use default CE) -> Key Value - V2
	log.Infof("3. Create CA2 in Lamassu (Try engine different from default CE. If not possible, use default CE) -> Key Value - V2")
	engines, _ := caClient.GetCryptoEngineProvider(context.Background())
	caDur2 := models.TimeDuration(time.Hour * 10)
	caIss2 := models.TimeDuration(time.Minute * 5)

	var engine *cmodels.CryptoEngineProvider
	for i := range engines {
		fmt.Println(engines[i].Name)
		if engines[i].Name == "Key Value - V2" {
			engine = engines[i]
		}
	}

	ca2, err := caClient.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:        cmodels.KeyMetadata{Type: cmodels.KeyType(x509.RSA), Bits: 2048},
		Subject:            cmodels.Subject{CommonName: "CA1"},
		CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDur2},
		IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss2},
		EngineID:           engine.ID,
	})
	if err != nil {
		return err
	}

	//4. Sync CA1 with AWS
	log.Infof("4. Sync CA1 with AWS")
	//4.1 Update the ca status in order to define the ca metadata to connect to AWS
	//Comment -> The functionality is not working due to aws-connector service is not working properly.
	metaUpdateData := map[string]interface{}{
		fmt.Sprintf("lamassu.io/iot/aws.%s", awsAccountID): models.IoTAWSCAMetadata{
			Registration: models.IoTAWSCAMetadataRegistration{
				RegistrationRequestTime: time.Now(),
				Status:                  models.IoTAWSCAMetadataRegistrationRequested,
			},
		},
	}

	ca2Upd, err := caClient.UpdateCAMetadata(context.Background(), services.UpdateCAMetadataInput{
		CAID:     ca1.ID,
		Metadata: metaUpdateData,
	})

	fmt.Println(ca2Upd)
	if err != nil {
		return err
	}

	//5. Create DMS with enrollment CA1 and validation CA2. Add CA1 in CACerts. Enable AWS Sync (RegMode: Auto)
	log.Infof("5. Create DMS with enrollment CA1 and validation CA2. Add CA1 in CACerts. Enable AWS Sync (RegMode: Auto)")
	dmsCreateInput := services.CreateDMSInput{
		Name: "My DMS",
		ID:   dmsID,
		Metadata: map[string]any{
			fmt.Sprintf("lamassu.io/iot/aws.%s", awsAccountID): models.IotAWSDMSMetadata{
				RegistrationMode: models.AutomaticAWSIoTRegistrationMode,
				JITPProvisioningTemplate: struct {
					ARN                 string "json:\"arn,omitempty\""
					AWSCACertificateId  string "json:\"aws_ca_id,omitempty\""
					ProvisioningRoleArn string "json:\"provisioning_role_arn\""
					EnableTemplate      bool   "json:\"enable_template\""
				}{
					EnableTemplate: false,
				},
				GroupNames: []string{"TEST-LMS"},
				Policies: []models.AWSIoTPolicy{
					{PolicyName: "my-p", PolicyDocument: p},
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
					AuthMode: models.ESTAuthMode(identityextractors.IdentityExtractorClientCertificate),
					AuthOptionsMTLS: models.AuthOptionsClientCertificate{
						ValidationCAs:        []string{ca2.ID},
						ChainLevelValidation: -1,
					},
				},
				DeviceProvisionProfile: models.DeviceProvisionProfile{
					Icon:      "BiSolidCreditCardFront",
					IconColor: "#25ee32-#222222",
					Metadata:  map[string]any{},
					Tags:      []string{"iot", "testdms", "cloud"},
				},
				EnrollmentCA:                ca1.ID,
				RegistrationMode:            models.JITP,
				EnableReplaceableEnrollment: true,
			},
			ReEnrollmentSettings: models.ReEnrollmentSettings{
				AdditionalValidationCAs:     []string{},
				ReEnrollmentDelta:           models.TimeDuration(time.Hour),
				EnableExpiredRenewal:        true,
				PreventiveReEnrollmentDelta: models.TimeDuration(time.Minute * 3),
				CriticalReEnrollmentDelta:   models.TimeDuration(time.Minute * 2),
			},
			CADistributionSettings: models.CADistributionSettings{
				IncludeLamassuSystemCA: true,
				IncludeEnrollmentCA:    true,
				ManagedCAs:             []string{},
			},
		},
	}

	_, err = dmsClient.CreateDMS(context.Background(), dmsCreateInput)
	if err != nil {
		return err
	}

	//6. Sign Bootstrap Cert with CA2
	log.Infof("6. Sign Bootstrap Cert with CA2")
	bootKey, err := chelpers.GenerateRSAKey(2048)
	if err != nil {
		return err
	}

	bootCsr, err := chelpers.GenerateCertificateRequest(cmodels.Subject{CommonName: "boot-crt"}, bootKey)
	if err != nil {
		return err
	}
	log.Infof("6. Sign Bootstrap Cert with CA2")
	bootSigedCrt, err := caClient.SignCertificate(context.Background(), services.SignCertificateInput{
		CAID:         ca2.ID,
		CertRequest:  (*models.X509CertificateRequest)(bootCsr),
		SignVerbatim: true,
	})
	if err != nil {
		return err
	}

	//7.1.1
	// 	Generate Device Key. Then generate the CSR used while enrolling
	// 	Generate Device Key and CSR
	log.Infof("7.1	Device 1:")
	devKey, err := chelpers.GenerateRSAKey(2048)
	if err != nil {
		return err
	}

	deviceCsr, err := chelpers.GenerateCertificateRequest(cmodels.Subject{CommonName: fmt.Sprintf("device-%d", time.Now().Unix())}, devKey)
	if err != nil {
		return err
	}

	estCli := est.Client{
		PrivateKey:            bootKey,
		Certificates:          []*x509.Certificate{(*x509.Certificate)(bootSigedCrt.Certificate)},
		InsecureSkipVerify:    true,
		Host:                  fmt.Sprintf("%s:%d/api/dmsmanager", hostname, port),
		AdditionalPathSegment: dmsCreateInput.ID,
	}

	log.Infof("7.1.1		Enroll with Lamassu")
	deviceCrt, err := estCli.Enroll(context.Background(), deviceCsr)
	if err != nil {
		return err
	}

	//7.1.2     Connect to AWS IoT Core

	err = writeCrtKey(deviceCrt, devKey, 0)
	if err != nil {
		return err
	}

	//Definition of the metadata for the update of dms

	fmt.Println("Connecting")
	keystr, err := chelpers.PrivateKeyToPEM(devKey)
	if err != nil {
		return err
	}

	err = os.WriteFile("device.key", []byte(keystr), 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile("device.crt", []byte(chelpers.CertificateToPEM(deviceCrt)), 0644)
	if err != nil {
		return err
	}

	var messagePubHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
		fmt.Printf("Received message: %s from topic: %s\n", msg.Payload(), msg.Topic())
	}

	var connectHandler mqtt.OnConnectHandler = func(client mqtt.Client) {
		fmt.Println("Connected")
	}

	var connectLostHandler mqtt.ConnectionLostHandler = func(client mqtt.Client, err error) {
		fmt.Printf("Connect lost: %v", err)
	}

	var broker = awsIotCoreEndpoint
	var mqttPort = 8883
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("ssl://%s:%d", broker, mqttPort))
	opts.SetClientID(deviceID)

	//shadowName := "shadow"
	//shadowName = shadowName + "/name/" + awsNamedShadowName

	awsCreds, err := tls.LoadX509KeyPair("device.crt", "device.key")
	if err != nil {
		return err
	}

	opts.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{awsCreds},
	}

	tryConnectAWSCount := 0
	var client mqtt.Client

	connect := func() error {
		opts.SetDefaultPublishHandler(messagePubHandler)
		opts.OnConnect = connectHandler
		opts.OnConnectionLost = connectLostHandler
		client = mqtt.NewClient(opts)
		if token := client.Connect(); token.Wait() && token.Error() != nil {
			return token.Error()
		}
		return nil
	}
	log.Infof("7.1.2		Connect to AWS IoT Core")
	for {
		err = connect()
		if err == nil {
			break
		} else {
			if tryConnectAWSCount >= 2 {
				return fmt.Errorf("tried %d times connecting to AWS. Last error: %s", tryConnectAWSCount, err)
			}
		}

		tryConnectAWSCount++
	}

	time.Sleep(time.Second * 3)

	fmt.Println("The DMS status has been modified to connect with IOT core")

	log.Infof("7.1.3		Wait 5 seconds and FORCE Reenroll via AWS Shadow")

	time.Sleep(5 * time.Second)

	//7.1.4     ReEnroll on shadow Update
	log.Infof("7.1.4		ReEnroll on shadow Update")
	crt, err := estCli.Reenroll(context.Background(), deviceCsr)

	fmt.Println(crt)

	if err != nil {
		return err
	}

	time.Sleep(time.Second * 3)

	//7.1.5 Dissconnect and ReConnect to AWS IoT Core -> Falta por desarrollar esta parte, no encuentro ningún ejemplo para desarrollarlo

	////////////////DEVICE 2 //////////////////////////////////

	//Enroll offline out of band

	dev2Key, err := chelpers.GenerateRSAKey(2048)

	if err != nil {
		return err
	}

	crDev2, err := chelpers.GenerateSelfSignedCertificate(dev2Key, fmt.Sprintf("device-%d", time.Now().Unix()))

	if err != nil {
		return err
	}

	fmt.Println(crDev2)

	//Importing the certificate to Lamassu

	return nil

}

func writeCrtKey(crt *x509.Certificate, key any, idx int) error {
	keystr, err := chelpers.PrivateKeyToPEM(key)
	if err != nil {
		return err
	}

	err = os.WriteFile(fmt.Sprintf("device-%d.key", idx), []byte(keystr), 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile(fmt.Sprintf("device-%d.crt", idx), []byte(chelpers.CertificateToPEM(crt)), 0644)
	if err != nil {
		return err
	}

	return nil
}
