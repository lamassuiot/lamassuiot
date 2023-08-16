package services

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/iotdataplane"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
)

type IotAWSService interface {
	GetAccountInfo() *models.IotAWSAccountInfo

	GetRegisteredCAs(input GetRegisteredCAsInput) ([]*models.CACertificate, error)
	RegisterCA(input RegisterCAInput) error
}

type iotAWSServiceImpl struct {
	accountID       string
	logger          *logrus.Entry
	iotdataplaneSDK *iotdataplane.Client
	iotSDK          *iot.Client
	caSDK           CAService
}

type IotAWSServiceBuilder struct {
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
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(builder.Conf.AccessKeyID, builder.Conf.SecretAccessKey, "")),
	})

	iotdataplaneClient := iotdataplane.New(iotdataplane.Options{
		HTTPClient:  iotdataplaneHttpCli,
		Region:      builder.Conf.Region,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(builder.Conf.AccessKeyID, builder.Conf.SecretAccessKey, "")),
	})

	stsCli := sts.New(sts.Options{
		HTTPClient:  stsHttpCli,
		Region:      builder.Conf.Region,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(builder.Conf.AccessKeyID, builder.Conf.SecretAccessKey, "")),
	})

	callIDOutput, err := stsCli.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}

	return &iotAWSServiceImpl{
		accountID:       *callIDOutput.Account,
		iotdataplaneSDK: iotdataplaneClient,
		iotSDK:          iotClient,
		logger:          builder.Logger,
		caSDK:           builder.CACli,
	}, nil
}

func (svc *iotAWSServiceImpl) GetAccountInfo() *models.IotAWSAccountInfo {
	descEndOut, err := svc.iotSDK.DescribeEndpoint(context.Background(), &iot.DescribeEndpointInput{
		EndpointType: aws.String("iot:Data-ATS"),
	})
	if err != nil {
		svc.logger.Errorf("could not describe iot:Data-ATS endpoint: %s", err)
		return nil
	}

	return &models.IotAWSAccountInfo{
		AccountID:       svc.accountID,
		IotMQTTEndpoint: *descEndOut.EndpointAddress,
	}
}

type RegisterCAInput struct {
	*models.CACertificate
}

func (svc *iotAWSServiceImpl) RegisterCA(input RegisterCAInput) error {
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
	svc.logger.Debugf("signing validation csr with cn=%s", csr.Subject.CommonName)
	singOutput, err := svc.caSDK.SignCertificate(SignCertificateInput{
		CAID:         input.ID,
		CertRequest:  &csr,
		SignVerbatim: true,
	})
	if err != nil {
		svc.logger.Errorf("something went wrong while requesting sign certificate: %s", err)
		return err
	}

	validationCert := singOutput.Certificate.String()
	validationCertBytes, err := base64.StdEncoding.DecodeString(validationCert)
	if err != nil {
		svc.logger.Errorf("could not decode b64 validation certificate: %s", err)
		return err
	}

	caCert := input.CACertificate.Certificate.Certificate.String()
	caCertBytes, err := base64.StdEncoding.DecodeString(caCert)
	if err != nil {
		svc.logger.Errorf("could not decode b64 CA certificate: %s", err)
		return err
	}

	svc.logger.Debugf("registering id=%s cn=%s CA certificate in AWS", input.ID, input.Certificate.Subject.CommonName)
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
		svc.logger.Errorf("something went wrong while registering CA certificate in AWS IoT: %s", err)
		return err
	}

	return nil
}

type GetRegisteredCAsInput struct {
}

func (svc *iotAWSServiceImpl) GetRegisteredCAs(input GetRegisteredCAsInput) ([]*models.CACertificate, error) {
	cas := []*models.CACertificate{}
	lmsCAs := 0
	totalAWSRegCAs := 0

	svc.logger.Debugf("listing CA certificates in AWS IoT")
	res, err := svc.iotSDK.ListCACertificates(context.Background(), &iot.ListCACertificatesInput{})
	if err != nil {
		svc.logger.Errorf("something went wrong while listing CA certificates from AWS IoT: %s", err)
		return cas, err
	}

	for _, caMeta := range res.Certificates {
		totalAWSRegCAs++

		descRes, err := svc.iotSDK.DescribeCACertificate(context.Background(), &iot.DescribeCACertificateInput{CertificateId: caMeta.CertificateId})
		if err != nil {
			svc.logger.Errorf("something went wrong while describing '%s' CA certificate from AWS IoT: %s", *caMeta.CertificateId, err)
			return cas, err
		}

		descCrt, err := helpers.ParseCertificate(*descRes.CertificateDescription.CertificatePem)
		if err != nil {
			svc.logger.Errorf("something went wrong while parsing PEM from CA certificate '%s': %s", *caMeta.CertificateId, err)
			return cas, err
		}

		svc.logger.Debugf("requesting CA with ID '%s' which has SN '%s' to CA service", *caMeta.CertificateId, helpers.SerialNumberToString(descCrt.SerialNumber))

		lmsCA, err := svc.caSDK.GetCABySerialNumber(GetCABySerialNumberInput{SerialNumber: helpers.SerialNumberToString(descCrt.SerialNumber)})
		if err != nil {
			svc.logger.Errorf("skipping CA with ID '%s' which has SN '%s'. Could not get CA from CA service '%s': %s", *caMeta.CertificateId, helpers.SerialNumberToString(descCrt.SerialNumber), err)
			continue
		}

		lmsCAs++

		cas = append(cas, lmsCA)
	}

	return cas, nil
}
