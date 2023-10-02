package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/iotdataplane"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

type IotAWSService interface {
	EventHandler(cloudEvent *event.Event)

	IoTService[models.IotAWSAccountInfo, models.IotAWSAccountInfo]

	GetRegisteredCAs(input GetRegisteredCAsInput) ([]*models.CACertificate, error)
	RegisterCA(input RegisterCAInput) error
}

type iotAWSServiceImpl struct {
	connectorID     string
	accountID       string
	logger          *logrus.Entry
	iotdataplaneSDK *iotdataplane.Client
	iotSDK          *iot.Client
	caSDK           CAService
}

type IotAWSServiceBuilder struct {
	ConnectorID    string
	Conf           config.AWSSDKConfig
	Logger         *logrus.Entry
	BaseHttpClient *http.Client
	CACli          CAService
}

func NewIotAWS(builder IotAWSServiceBuilder) (IotAWSService, error) {
	iotLogger := builder.Logger.WithField("sdk", "AWS IoT Client")
	iotdataplaneLogger := builder.Logger.WithField("sdk", "AWS IoT Dataplane Client")
	stsLogger := builder.Logger.WithField("sdk", "AWS STS Client")

	iotHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(builder.BaseHttpClient, iotLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT http client with tracer: %s", err)
		return nil, err
	}

	iotdataplaneHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(builder.BaseHttpClient, iotdataplaneLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT http client with tracer: %s", err)
		return nil, err
	}

	stsHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(builder.BaseHttpClient, stsLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT http client with tracer: %s", err)
		return nil, err
	}

	iotClient := iot.New(iot.Options{
		HTTPClient:  iotHttpCli,
		Region:      builder.Conf.Region,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(builder.Conf.AccessKeyID, string(builder.Conf.SecretAccessKey), "")),
	})

	iotdataplaneClient := iotdataplane.New(iotdataplane.Options{
		HTTPClient:  iotdataplaneHttpCli,
		Region:      builder.Conf.Region,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(builder.Conf.AccessKeyID, string(builder.Conf.SecretAccessKey), "")),
	})

	stsCli := sts.New(sts.Options{
		HTTPClient:  stsHttpCli,
		Region:      builder.Conf.Region,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(builder.Conf.AccessKeyID, string(builder.Conf.SecretAccessKey), "")),
	})

	callIDOutput, err := stsCli.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}

	return &iotAWSServiceImpl{
		connectorID:     builder.ConnectorID,
		accountID:       *callIDOutput.Account,
		iotdataplaneSDK: iotdataplaneClient,
		iotSDK:          iotClient,
		logger:          builder.Logger,
		caSDK:           builder.CACli,
	}, nil
}

func getEventBody[E any](cloudEvent *event.Event) (*E, error) {
	var elem *E
	eventDataBytes := cloudEvent.Data()
	err := json.Unmarshal(eventDataBytes, &elem)
	return elem, err
}

func (svc *iotAWSServiceImpl) EventHandler(cloudEvent *event.Event) {
	lFunc := svc.logger.WithField("req-id", cloudEvent.ID())
	logError := func(eventID string, eventType string, modelObject string, err error) {
		lFunc.Errorf("could not decode event '%s' into model '%s' object. Skipping event: %s", eventType, modelObject, err)
	}

	switch cloudEvent.Type() {
	case "ca.create", "ca.import", "ca.update.metadata":
		ca, err := getEventBody[models.CACertificate](cloudEvent)
		if err != nil {
			logError(cloudEvent.ID(), cloudEvent.Type(), "CACertificate", err)
			return
		}

		var meta interface{}
		var ok bool
		if meta, ok = ca.Metadata[svc.connectorID]; !ok {
			lFunc.Debugf("skipping event of type %s. Metadata didn't include connector ID (%s)", cloudEvent.Type(), svc.connectorID)
			return
		}

		metaBytes, err := json.Marshal(meta)
		if err != nil {
			lFunc.Errorf("skipping event of type %s with ID %s. Invalid metadata content. Got metadata \n%s\n error is: %s", cloudEvent.Type(), cloudEvent.ID(), meta, err)
			return
		}

		unquoteMeta, err := strconv.Unquote(string(metaBytes))
		if err != nil {
			lFunc.Warnf("event of type %s with ID %s. metadata is not quoted. continuing", cloudEvent.Type(), cloudEvent.ID())
		}
		metaBytes = []byte(unquoteMeta)

		var metaCAReg models.CAIoTAWSRegistration
		if err = json.Unmarshal(metaBytes, &metaCAReg); err != nil {
			lFunc.Errorf("skipping event of type %s with ID %s. Invalid metadata format. Got metadata \n%s\n error is: %s", cloudEvent.Type(), cloudEvent.ID(), meta, err)
			return
		}

		if !metaCAReg.Register {
			lFunc.Warnf("skipping event of type %s with ID %s. Register attribute should be true. Got metadata \n%s", cloudEvent.Type(), cloudEvent.ID(), meta)
			return
		}

		//check if CA already registered in AWS
		cas, err := svc.GetRegisteredCAs(GetRegisteredCAsInput{})
		if err != nil {
			lFunc.Errorf("skipping event of type %s with ID %s. Could not get AWS Registered CAs", cloudEvent.Type(), cloudEvent.ID())
			return
		}

		alreadyRegistered := false
		idx := slices.IndexFunc[*models.CACertificate](cas, func(c *models.CACertificate) bool {
			if c.SerialNumber == ca.SerialNumber {
				return true
			} else {
				return false
			}
		})

		if idx != -1 {
			alreadyRegistered = true
		}

		if !alreadyRegistered {
			lFunc.Debugf("registering CA with SN '%s'", ca.SerialNumber)
			err := svc.RegisterCA(RegisterCAInput{CACertificate: ca})
			if err != nil {
				lFunc.Errorf("something went wrong while registering CA with SN '%s' in AWS IoT. Skipping event handling: %s", ca.SerialNumber, err)
				return
			}
		} else {
			lFunc.Warnf("CA with SN '%s' is already registered in AWS IoT. Skipping registration process", ca.SerialNumber)
		}

		//once CA is registered, check if JITP is required
		if !metaCAReg.JITP {
			lFunc.Warnf("event of type %s with ID %s. No JITP Template will be created/updated. Got metadata \n%s", cloudEvent.Type(), cloudEvent.ID(), meta)
			return
		}

		//check if JITP template already exists. If so, update it if required
	}
}

func (svc *iotAWSServiceImpl) GetCloudProviderConfig() (*models.IotAWSAccountInfo, error) {
	lFunc := svc.logger

	descEndOut, err := svc.iotSDK.DescribeEndpoint(context.Background(), &iot.DescribeEndpointInput{
		EndpointType: aws.String("iot:Data-ATS"),
	})
	if err != nil {
		lFunc.Errorf("could not describe iot:Data-ATS endpoint: %s", err)
		return nil, fmt.Errorf("could not describe iot:Data-ATS endpoint")
	}

	return &models.IotAWSAccountInfo{
		AccountID:       svc.accountID,
		IotMQTTEndpoint: *descEndOut.EndpointAddress,
	}, nil
}

func (svc *iotAWSServiceImpl) GetDeviceConfiguration(input *GetDeviceConfigurationInput) (*models.IotAWSAccountInfo, error) {
	return nil, fmt.Errorf("TODO")
}

type RegisterCAInput struct {
	*models.CACertificate
}

func (svc *iotAWSServiceImpl) RegisterCA(input RegisterCAInput) error {
	lFunc := svc.logger

	regCode, err := svc.iotSDK.GetRegistrationCode(context.Background(), &iot.GetRegistrationCodeInput{})
	if err != nil {
		return err
	}

	key, err := helpers.GenerateRSAKey(2048)
	if err != nil {
		return err
	}

	regCodeCSR, err := helpers.GenerateCertificateRequest(models.Subject{CommonName: *regCode.RegistrationCode}, key)
	if err != nil {
		return err
	}

	csr := models.X509CertificateRequest(*regCodeCSR)
	// Sign verification certificate CSR
	lFunc.Debugf("signing validation csr with cn=%s", csr.Subject.CommonName)
	singOutput, err := svc.caSDK.SignCertificate(context.Background(), SignCertificateInput{
		CAID:         input.ID,
		CertRequest:  &csr,
		SignVerbatim: true,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while requesting sign certificate: %s", err)
		return err
	}

	validationCert := singOutput.Certificate.String()
	validationCertBytes, err := base64.StdEncoding.DecodeString(validationCert)
	if err != nil {
		lFunc.Errorf("could not decode b64 validation certificate: %s", err)
		return err
	}

	caCert := input.CACertificate.Certificate.Certificate.String()
	caCertBytes, err := base64.StdEncoding.DecodeString(caCert)
	if err != nil {
		lFunc.Errorf("could not decode b64 CA certificate: %s", err)
		return err
	}

	lFunc.Debugf("registering id=%s cn=%s CA certificate in AWS", input.ID, input.Certificate.Subject.CommonName)
	_, err = svc.iotSDK.RegisterCACertificate(context.Background(), &iot.RegisterCACertificateInput{
		CaCertificate:           aws.String(string(caCertBytes)),
		VerificationCertificate: aws.String(string(validationCertBytes)),
		Tags: []types.Tag{
			types.Tag{
				Key:   aws.String("LMS.CAID"),
				Value: &input.ID,
			},
		},
	})
	if err != nil {
		lFunc.Errorf("something went wrong while registering CA certificate in AWS IoT: %s", err)
		return err
	}

	return nil
}

type GetRegisteredCAsInput struct {
}

func (svc *iotAWSServiceImpl) GetRegisteredCAs(input GetRegisteredCAsInput) ([]*models.CACertificate, error) {
	lFunc := svc.logger

	cas := []*models.CACertificate{}

	lmsCAs := 0
	totalAWSRegCAs := 0

	lFunc.Debugf("listing CA certificates in AWS IoT")
	nextMarker := ""

	continueIter := true
	for continueIter {
		res, err := svc.iotSDK.ListCACertificates(context.Background(), &iot.ListCACertificatesInput{
			PageSize: aws.Int32(2),
			Marker:   &nextMarker,
		})

		if err != nil {
			lFunc.Errorf("something went wrong while listing CA certificates from AWS IoT: %s", err)
			return cas, err
		}

		for _, caMeta := range res.Certificates {
			totalAWSRegCAs++

			descRes, err := svc.iotSDK.DescribeCACertificate(context.Background(), &iot.DescribeCACertificateInput{CertificateId: caMeta.CertificateId})
			if err != nil {
				lFunc.Errorf("something went wrong while describing '%s' CA certificate from AWS IoT: %s", *caMeta.CertificateId, err)
				return cas, err
			}

			descCrt, err := helpers.ParseCertificate(*descRes.CertificateDescription.CertificatePem)
			if err != nil {
				lFunc.Errorf("something went wrong while parsing PEM from CA certificate '%s': %s", *caMeta.CertificateId, err)
				return cas, err
			}

			lFunc.Debugf("requesting CA with ID '%s' which has SN '%s' to CA service", *caMeta.CertificateId, helpers.SerialNumberToString(descCrt.SerialNumber))

			lmsCA, err := svc.caSDK.GetCABySerialNumber(context.Background(), GetCABySerialNumberInput{SerialNumber: helpers.SerialNumberToString(descCrt.SerialNumber)})
			if err != nil {
				lFunc.Errorf("skipping CA with ID '%s' which has SN '%s'. Could not get CA from CA service: %s", *caMeta.CertificateId, helpers.SerialNumberToString(descCrt.SerialNumber), err)
				continue
			}
			lmsCAs++

			cas = append(cas, lmsCA)
			if *res.NextMarker != "" {
				lFunc.Debugf("Next marker: %s", *res.NextMarker)
				nextMarker = *res.NextMarker
			} else {
				lFunc.Debugf("No marker")
				continueIter = false
			}
		}
	}

	return cas, nil
}
