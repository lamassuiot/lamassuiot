package iotplatform

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/iotdataplane"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

type AWSIotPlatformService struct {
	connectorID     string
	accountID       string
	region          string
	logger          *logrus.Entry
	iotdataplaneSDK *iotdataplane.Client
	iotSDK          *iot.Client
	caSDK           services.CAService
}

type AWSIotPlatformServiceBuilder struct {
	ConnectorID    string
	Conf           aws.Config
	Logger         *logrus.Entry
	BaseHttpClient *http.Client
	CACli          services.CAService
}

func NewAWSIotPlatformService(builder AWSIotPlatformServiceBuilder) (IotPlatformService, error) {
	iotLogger := builder.Logger.WithField("sdk", "AWS IoT Client")
	iotdataplaneLogger := builder.Logger.WithField("sdk", "AWS IoT DataPlane Client")
	stsLogger := builder.Logger.WithField("sdk", "AWS STS Client")

	// derefIotHttpCli := &builder.BaseHttpClient
	iotHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(&http.Client{}, iotLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT http client with tracer: %s", err)
		return nil, err
	}

	iotdataplaneHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(&http.Client{}, iotdataplaneLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT http client with tracer: %s", err)
		return nil, err
	}

	stsHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(&http.Client{}, stsLogger)
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

	return &AWSIotPlatformService{
		connectorID:     builder.ConnectorID,
		accountID:       *callIDOutput.Account,
		region:          builder.Conf.Region,
		iotdataplaneSDK: iotdataplaneClient,
		iotSDK:          iotClient,
		logger:          builder.Logger,
		caSDK:           builder.CACli,
	}, nil
}

func (svc *AWSIotPlatformService) GetCloudConfiguration(context.Context) (any, error) {
	return nil, nil
}

func (svc *AWSIotPlatformService) GetRegisteredCAs(context.Context) ([]*models.CACertificate, error) {
	lFunc := svc.logger
	cas := []*models.CACertificate{}
	lmsCAs := 0
	totalAWSRegCAs := 0

	lFunc.Debugf("listing CA certificates in AWS IoT")
	nextMarker := ""

	continueIter := true
	for continueIter {
		res, err := svc.iotSDK.ListCACertificates(context.
			Background(), &iot.ListCACertificatesInput{
			PageSize: aws.Int32(10),
			Marker:   &nextMarker,
		})
		if err != nil {
			lFunc.Errorf("something went wrong while listing CA certificates from AWS IoT: %s", err)
			return cas, err
		}

		if len(res.Certificates) == 0 {
			continueIter = false
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
			if res.NextMarker != nil && *res.NextMarker != "" {
				lFunc.Debugf("Next marker: %s", *res.NextMarker)
				nextMarker = *res.NextMarker
			} else {
				lFunc.Debugf("No marker")
				continueIter = false
			}
			lmsCA, err := svc.caSDK.GetCABySerialNumber(context.Background(), services.GetCABySerialNumberInput{SerialNumber: helpers.SerialNumberToString(descCrt.SerialNumber)})
			if err != nil {
				lFunc.Warnf("skipping CA with ID '%s' which has SN '%s'. Could not get CA from CA service: %s", *caMeta.CertificateId, helpers.SerialNumberToString(descCrt.SerialNumber), err)
				continue
			}
			lmsCAs++
			cas = append(cas, lmsCA)
		}
	}

	return cas, nil
}

func (svc *AWSIotPlatformService) RegisterCA(ctx context.Context, input RegisterCAInput) (*models.CACertificate, error) {
	lFunc := svc.logger

	regCode, err := svc.iotSDK.GetRegistrationCode(context.Background(), &iot.GetRegistrationCodeInput{})
	if err != nil {
		return nil, err
	}

	key, err := helpers.GenerateRSAKey(2048)
	if err != nil {
		return nil, err
	}

	regCodeCSR, err := helpers.GenerateCertificateRequest(models.Subject{CommonName: *regCode.RegistrationCode}, key)
	if err != nil {
		return nil, err
	}

	csr := models.X509CertificateRequest(*regCodeCSR)
	// Sign verification certificate CSR
	lFunc.Debugf("signing validation csr with cn=%s", csr.Subject.CommonName)
	singOutput, err := svc.caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
		CAID:         input.CACertificate.ID,
		CertRequest:  &csr,
		SignVerbatim: true,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while requesting sign certificate: %s", err)
		return nil, err
	}

	validationCert := singOutput.Certificate.String()
	validationCertBytes, err := base64.StdEncoding.DecodeString(validationCert)
	if err != nil {
		lFunc.Errorf("could not decode b64 validation certificate: %s", err)
		return nil, err
	}

	caCert := input.CACertificate.Certificate.Certificate.String()
	caCertBytes, err := base64.StdEncoding.DecodeString(caCert)
	if err != nil {
		lFunc.Errorf("could not decode b64 CA certificate: %s", err)
		return nil, err
	}

	lFunc.Debugf("registering id=%s cn=%s CA certificate in AWS", input.ID, input.Certificate.Subject.CommonName)
	regResponse, err := svc.iotSDK.RegisterCACertificate(context.Background(), &iot.RegisterCACertificateInput{
		CaCertificate:           aws.String(string(caCertBytes)),
		VerificationCertificate: aws.String(string(validationCertBytes)),
		Tags: []types.Tag{
			{
				Key:   aws.String("LMS.CA.ID"),
				Value: &input.ID,
			},
			{
				Key:   aws.String("LMS.CA.SN"),
				Value: &input.SerialNumber,
			},
			{
				Key:   aws.String("LMS.CA.CN"),
				Value: &input.Subject.CommonName,
			},
		},
	})
	if err != nil {
		lFunc.Errorf("something went wrong while registering CA certificate in AWS IoT: %s", err)
		return nil, err
	}

	newMeta := input.Metadata
	newMeta[fmt.Sprintf("lamassu.io/iot-platform-connector/aws/%s/config", svc.connectorID)] = models.PlatformConnectorAWSCAMetadata{
		Account:       svc.accountID,
		Region:        svc.region,
		ARN:           *regResponse.CertificateArn,
		CertificateID: *regResponse.CertificateId,
	}

	lFunc.Infof("updating CA %s with new metadata: %s\n", input.ID, newMeta)

	ca, err := svc.caSDK.UpdateCAMetadata(ctx, services.UpdateCAMetadataInput{
		CAID:     input.ID,
		Metadata: newMeta,
	})

	if err != nil {
		lFunc.Errorf("could not update CA metadata: %s", err)
	}

	return ca, nil
}

func (svc *AWSIotPlatformService) RegisterUpdateJITPProvisioner(ctx context.Context, input RegisterJITPProvisionerInput) (map[string]any, error) {
	lFunc := svc.logger
	var awsPlatformConfig models.DMSMetadataIotPlatformAWS
	hasKey, err := helpers.GetMetadataToStruct(input.DMS.Metadata, models.DeviceMetadataIotAutomationKey(svc.connectorID), &awsPlatformConfig)
	if err != nil {
		lFunc.Errorf("error while getting key %s from DMS Metadata: %s", models.DeviceMetadataIotAutomationKey(svc.connectorID), err)
		return nil, err
	}

	if !hasKey {
		return nil, fmt.Errorf("DMS does not have %s key. Invalid DMS", models.DeviceMetadataIotAutomationKey(svc.connectorID))
	}

	policies := []string{}
	for _, policy := range awsPlatformConfig.JITPProvisioningTemplate.JITPPolicies {
		//TODO: Create/Update Iot policies
		policies = append(policies, policy.Name)
	}

	templateBody := jitpTemplateBuilder(awsPlatformConfig.JITPProvisioningTemplate.JITPGroupNames, policies)
	fmt.Println(templateBody)

	provRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/JITPRole", svc.accountID)
	lFunc.Warnf("Make sure %s IAM Role exists", provRoleARN)
	_, err = svc.iotSDK.CreateProvisioningTemplate(context.Background(), &iot.CreateProvisioningTemplateInput{
		ProvisioningRoleArn: aws.String(provRoleARN),
		TemplateBody:        &templateBody,
		TemplateName:        &input.DMS.ID,
		Description:         &input.DMS.Name,
		Enabled:             awsPlatformConfig.JITPProvisioningTemplate.EnableTemplate,
		PreProvisioningHook: nil,
		Tags:                []types.Tag{types.Tag{Key: aws.String("created-by"), Value: aws.String("LAMASSU")}},
		Type:                types.TemplateTypeJitp,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while creating JITP template in AWS: %s", err)
		return nil, err
	}

	return nil, nil

}

func jitpTemplateBuilder(thingGroups []string, policyNames []string) string {
	policiesSection := []string{}
	for _, policyName := range policyNames {
		policy := `"policy":{
			"Type":"AWS::IoT::Policy",
			"Properties":{
			   "PolicyName":"` + policyName + `"
			}
		 }`
		policiesSection = append(policiesSection, policy)
	}

	jitpTemplate := `{
		"Parameters":{
			"AWS::IoT::Certificate::Country":{
			   "Type":"String"
			},
			"AWS::IoT::Certificate::Organization":{
			   "Type":"String"
			},
			"AWS::IoT::Certificate::OrganizationalUnit":{
			   "Type":"String"
			},
		   "AWS::IoT::Certificate::DistinguishedNameQualifier":{
			  "Type":"String"
		   },
		   "AWS::IoT::Certificate::StateName":{
			  "Type":"String"
		   },
		   "AWS::IoT::Certificate::CommonName":{
			  "Type":"String"
		   },
		   "AWS::IoT::Certificate::SerialNumber":{
			  "Type":"String"
		   },
		   "AWS::IoT::Certificate::Id":{
			  "Type":"String"
		   }
		},
		"Resources":{
		   "thing":{
			  "Type":"AWS::IoT::Thing",
				"Properties":{
				 "ThingName":{
					"Ref":"AWS::IoT::Certificate::CommonName"
				 },
				 "AttributePayload":{
					"version":"v1",
					"serialNumber":{
					   "Ref":"AWS::IoT::Certificate::SerialNumber"
					}
				 },
				 "ThingGroups":[
					` + strings.Join(thingGroups, ",") + `
				 ]
			  },
			  "OverrideSettings":{
				 "AttributePayload":"REPLACE",
				 "ThingTypeName":"REPLACE",
				 "ThingGroups":"REPLACE"
			  }
		   },
		   "certificate":{
			  "Type":"AWS::IoT::Certificate",
			  "Properties":{
				 "CertificateId":{
					"Ref":"AWS::IoT::Certificate::Id"
				 },
				 "Status":"ACTIVE"
			  }
		   },
		   ` + strings.Join(policiesSection, ",") + `
		}
	 }
	 `
	return jitpTemplate
}
