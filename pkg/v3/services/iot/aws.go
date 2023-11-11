package iot

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/iotdataplane"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

type AWSCloudConnectorService struct {
	iotSDK          iot.Client
	iotdataplaneSDK iotdataplane.Client
	region          string
	logger          *logrus.Entry
	endpointAddress string
	ConnectorID     string
	CaSDK           services.CAService
	DmsSDK          services.DMSManagerService
	DeviceSDK       services.DeviceManagerService
	AccountID       string
}

type AWSCloudConnectorBuilder struct {
	Conf        aws.Config
	Logger      *logrus.Entry
	ConnectorID string
	CaSDK       services.CAService
	DmsSDK      services.DMSManagerService
	DeviceSDK   services.DeviceManagerService
}

type shadowMsg struct {
	Reported map[string]any `json:"reported"`
	Desired  map[string]any `json:"desired"`
}

func NewAWSCloudConnectorServiceService(builder AWSCloudConnectorBuilder) (*AWSCloudConnectorService, error) {
	iotLogger := builder.Logger.WithField("sdk", "AWS IoT Client")
	idpLogger := builder.Logger.WithField("sdk", "AWS IoT Dataple Client")
	stsLogger := builder.Logger.WithField("sdk", "AWS STS Client")

	// derefIotHttpCli := &builder.BaseHttpClient
	iotHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(&http.Client{}, iotLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT http client with tracer: %s", err)
		return nil, err
	}

	idpHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(&http.Client{}, idpLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT Dataplane http client with tracer: %s", err)
		return nil, err
	}

	stsHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(&http.Client{}, stsLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT http client with tracer: %s", err)
		return nil, err
	}

	iotConf := builder.Conf
	iotConf.HTTPClient = iotHttpCli
	iotClient := iot.NewFromConfig(iotConf)

	iotdpConf := builder.Conf
	iotdpConf.HTTPClient = idpHttpCli
	iotdpClient := iotdataplane.NewFromConfig(iotdpConf)

	stsConf := builder.Conf
	stsConf.HTTPClient = stsHttpCli
	stsClient := sts.NewFromConfig(stsConf)

	callIDOutput, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}

	logger := logrus.WithField("svc", "aws-iot")
	if builder.Logger != nil {
		logger = builder.Logger
	}

	endpoint, err := iotClient.DescribeEndpoint(context.Background(), &iot.DescribeEndpointInput{
		EndpointType: aws.String("iot:Data-ATS"),
	})
	if err != nil {
		builder.Logger.Errorf("could not describe AWS account IoT Core Endpoint using 'iot:Data-ATS' endpoint type: %s", err)
		return nil, err
	}

	builder.Logger.Infof("connector is configured for account '%s', which uses iot:Data-ATS endpoint with uri %s", *callIDOutput.Account, *endpoint.EndpointAddress)

	return &AWSCloudConnectorService{
		iotSDK:          *iotClient,
		iotdataplaneSDK: *iotdpClient,
		logger:          logger,
		region:          builder.Conf.Region,
		endpointAddress: *endpoint.EndpointAddress,
		AccountID:       *callIDOutput.Account,
		ConnectorID:     builder.ConnectorID,
		CaSDK:           builder.CaSDK,
		DmsSDK:          builder.DmsSDK,
		DeviceSDK:       builder.DeviceSDK,
	}, nil
}

type UpdateDeviceShadowInput struct {
	DeviceID               string
	RemediationActionType  models.RemediationActionType
	DMSIoTAutomationConfig models.IotAWSDMSMetadata
}

func (svc *AWSCloudConnectorService) UpdateDeviceShadow(input UpdateDeviceShadowInput) error {
	if input.DMSIoTAutomationConfig.ShadowConfig.Enable {
		logrus.Warnf("shadow usage is not enabled for DMS associated to device %s. Skipping", input.DeviceID)
		return nil
	}

	getShadowReq := &iotdataplane.GetThingShadowInput{
		ThingName: aws.String(input.DeviceID),
	}
	if input.DMSIoTAutomationConfig.ShadowConfig.ShadowName != "" {
		logrus.Debugf("using a named shadow with name '%s'", input.DMSIoTAutomationConfig.ShadowConfig.ShadowName)
		getShadowReq.ShadowName = &input.DMSIoTAutomationConfig.ShadowConfig.ShadowName
	}

	getShadowOutput, err := svc.iotdataplaneSDK.GetThingShadow(context.Background(), getShadowReq)
	if err != nil {
		return fmt.Errorf("could not get device %s shadow: %s", input.DeviceID, err)
	}

	var deviceShadow shadowMsg
	err = json.Unmarshal(getShadowOutput.Payload, &deviceShadow)
	if err != nil {
		return fmt.Errorf("could not unmarshal device %s shadow: %s", input.DeviceID, err)
	}

	idShadow := map[string]int{}
	//check if shadow has "identity_actions" key
	if idAction, ok := deviceShadow.Desired["identity_actions"]; ok {
		//has key. Decode and update idShadow
		idActionBytes, err := json.Marshal(idAction)
		if err != nil {
			return fmt.Errorf("failed re-encoding 'identity_actions' object into bytes: %s", err)
		}

		err = json.Unmarshal(idActionBytes, &idShadow)
		if err != nil {
			return fmt.Errorf("failed decoding 'identity_actions': %s", err)
		}
	}

	idShadow[string(input.RemediationActionType)] = int(time.Now().UnixMilli())
	deviceShadow.Desired["identity_actions"] = idShadow

	deviceShadowBytes, err := json.Marshal(deviceShadow)
	if err != nil {
		return fmt.Errorf("failed encoding new shadow payload: %s", err)
	}

	shadowUpdateMsg := &iotdataplane.UpdateThingShadowInput{
		ThingName: &input.DeviceID,
		Payload:   deviceShadowBytes,
	}

	if input.DMSIoTAutomationConfig.ShadowConfig.ShadowName != "" {
		logrus.Debugf("using a named shadow with name '%s'", input.DMSIoTAutomationConfig.ShadowConfig.ShadowName)
		shadowUpdateMsg.ShadowName = &input.DMSIoTAutomationConfig.ShadowConfig.ShadowName
	}

	_, err = svc.iotdataplaneSDK.UpdateThingShadow(context.Background(), shadowUpdateMsg)
	if err != nil {
		logrus.Errorf("could not create Update Shadow for thing %s: %s", input.DeviceID, err)
		return err
	}

	logrus.Infof("updated shadow for device with %s", input.DeviceID)

	return nil
}

func (svc *AWSCloudConnectorService) GetRegisteredCAs(context.Context) ([]*models.CACertificate, error) {
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
			lmsCA, err := svc.CaSDK.GetCABySerialNumber(context.Background(), services.GetCABySerialNumberInput{SerialNumber: helpers.SerialNumberToString(descCrt.SerialNumber)})
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

type RegisterCAInput struct {
	models.CACertificate
	RegisterConfiguration models.IoTAWSCAMetadata
}

func (svc *AWSCloudConnectorService) RegisterCA(ctx context.Context, input RegisterCAInput) (*models.CACertificate, error) {
	lFunc := svc.logger

	//check if CA already registered in AWS
	cas, err := svc.GetRegisteredCAs(context.Background())
	if err != nil {
		logrus.Errorf("could not get Registered CAs: %s", err)
		return nil, err
	}

	alreadyRegistered := false
	idx := slices.IndexFunc(cas, func(c *models.CACertificate) bool {
		if c.SerialNumber == input.SerialNumber {
			return true
		} else {
			return false
		}
	})

	if idx != -1 {
		alreadyRegistered = true
	}

	if !alreadyRegistered {
		logrus.Infof("registering CA with SN '%s'", input.SerialNumber)
	} else {
		logrus.Warnf("CA with SN '%s' is already registered in AWS IoT. Skipping registration process", input.SerialNumber)
		return &input.CACertificate, nil
	}

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
	singOutput, err := svc.CaSDK.SignCertificate(context.Background(), services.SignCertificateInput{
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
	newMeta[models.AWSIoTMetadataKey(svc.ConnectorID)] = models.IoTAWSCAMetadata{
		Account:             svc.AccountID,
		Region:              svc.region,
		ARN:                 *regResponse.CertificateArn,
		CertificateID:       *regResponse.CertificateId,
		Register:            true,
		IotCoreMQTTEndpoint: svc.endpointAddress,
	}

	lFunc.Infof("updating CA %s with new metadata: %s\n", input.ID, newMeta)

	ca, err := svc.CaSDK.UpdateCAMetadata(ctx, services.UpdateCAMetadataInput{
		CAID:     input.ID,
		Metadata: newMeta,
	})
	if err != nil {
		lFunc.Errorf("could not update CA metadata: %s", err)
	}

	return ca, nil
}

type RegisterUpdateJITPProvisionerInput struct {
	DMS           *models.DMS
	AwsJITPConfig models.IotAWSDMSMetadata
}

func (svc *AWSCloudConnectorService) RegisterUpdateJITPProvisioner(ctx context.Context, input RegisterUpdateJITPProvisionerInput) error {
	lFunc := svc.logger

	policies := []string{}
	for _, policy := range input.AwsJITPConfig.JITPProvisioningTemplate.JITPPolicies {
		policies = append(policies, policy.PolicyName)
		iotPolicy, err := svc.iotSDK.GetPolicy(ctx, &iot.GetPolicyInput{
			PolicyName: &policy.PolicyName,
		})
		if err != nil {
			var rne *types.ResourceNotFoundException
			if !errors.As(err, &rne) {
				lFunc.Errorf("got error while getting %s policy: %s", policy.PolicyName, err)
				return err
			}

			buffer := new(bytes.Buffer)
			err := json.Compact(buffer, []byte(policy.PolicyDocument))
			if err != nil {
				lFunc.Errorf("got error while compacting %s policy: %s", policy.PolicyName, err)
				return err
			}

			policyDoc := buffer.String()

			_, err = svc.iotSDK.CreatePolicy(ctx, &iot.CreatePolicyInput{
				PolicyDocument: &policyDoc,
				PolicyName:     &policy.PolicyName,
			})
			if err != nil {
				lFunc.Errorf("got error while creating %s policy: %s", policy.PolicyName, err)
				return err
			}
		} else {
			plVersions, err := svc.iotSDK.ListPolicyVersions(ctx, &iot.ListPolicyVersionsInput{
				PolicyName: iotPolicy.PolicyName,
			})
			if err != nil {
				lFunc.Errorf("could not list policy versions for %s policy: %s", policy.PolicyName, err)
				return err
			}

			if len(plVersions.PolicyVersions) > 1 {
				sort.Slice(plVersions.PolicyVersions, func(i, j int) bool {
					return plVersions.PolicyVersions[i].CreateDate.After(*plVersions.PolicyVersions[j].CreateDate)
				})

				for _, p := range plVersions.PolicyVersions {
					if !p.IsDefaultVersion {
						lFunc.Infof("deleting version '%s' from policy %s", *p.VersionId, policy.PolicyName)
						_, err = svc.iotSDK.DeletePolicyVersion(ctx, &iot.DeletePolicyVersionInput{
							PolicyName:      iotPolicy.PolicyName,
							PolicyVersionId: p.VersionId,
						})
						if err != nil {
							lFunc.Errorf("got error while deleting version '%s' from policy %s: %s", *iotPolicy.DefaultVersionId, policy.PolicyName, err)
							return err
						}
					}
				}
			}
		}
	}

	templateBody, err := jitpTemplateBuilder(input.AwsJITPConfig.JITPProvisioningTemplate.JITPGroupNames, policies)
	if err != nil {
		lFunc.Errorf("got error while generating JITP Template: %s", err)
		return err
	}

	lFunc.Debugf("JITP '%s' template json document: \n%s", input.DMS.ID, templateBody)

	provRoleARN := input.AwsJITPConfig.JITPProvisioningTemplate.ProvisioningRoleArn
	if provRoleARN == "" {
		provRoleARN = fmt.Sprintf("arn:aws:iam::%s:role/JITPRole", svc.AccountID)
		lFunc.Warnf("using default provisioning role. Make sure %s IAM Role exists in the %s account", provRoleARN, svc.AccountID)
	}
	cpTemplate, err := svc.iotSDK.CreateProvisioningTemplate(context.Background(), &iot.CreateProvisioningTemplateInput{
		ProvisioningRoleArn: aws.String(provRoleARN),
		TemplateBody:        &templateBody,
		TemplateName:        &input.DMS.ID,
		Description:         &input.DMS.Name,
		Enabled:             input.AwsJITPConfig.JITPProvisioningTemplate.EnableTemplate,
		PreProvisioningHook: nil,
		Tags:                []types.Tag{types.Tag{Key: aws.String("created-by"), Value: aws.String("LAMASSU")}},
		Type:                types.TemplateTypeJitp,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while creating JITP template in AWS: %s", err)
		return err
	}

	lFunc.Infof("created JITP '%s' template", templateBody)

	if input.AwsJITPConfig.JITPProvisioningTemplate.AWSCACertificateId != "" {
		lFunc.Infof("updating AWS CA Certificate %s assigning JITP '%s' template", input.AwsJITPConfig.JITPProvisioningTemplate.AWSCACertificateId, input.DMS.ID)
		_, err = svc.iotSDK.UpdateCACertificate(context.Background(), &iot.UpdateCACertificateInput{
			CertificateId:             &input.AwsJITPConfig.JITPProvisioningTemplate.AWSCACertificateId,
			NewAutoRegistrationStatus: types.AutoRegistrationStatusEnable,
			NewStatus:                 types.CACertificateStatusActive,
			RegistrationConfig: &types.RegistrationConfig{
				TemplateName: &input.DMS.ID,
			},
			RemoveAutoRegistration: false,
		})
		if err != nil {
			lFunc.Errorf("something went wrong while updating CA Certificate: %s", err)
			return err
		}
	} else {
		lFunc.Warnf("not updating any AWS CA Certificate for JITP '%s' template", input.DMS.ID)
	}

	dms := input.DMS
	updatedJitpConf := input.AwsJITPConfig
	updatedJitpConf.JITPProvisioningTemplate.ARN = *cpTemplate.TemplateArn
	dms.Metadata[models.AWSIoTMetadataKey(svc.ConnectorID)] = updatedJitpConf

	_, err = svc.DmsSDK.UpdateDMS(ctx, services.UpdateDMSInput{
		DMS: *dms,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while updating DMS metadata: %s", err)
		return err
	}

	return nil
}

func jitpTemplateBuilder(thingGroups []string, policyNames []string) (string, error) {
	policiesSection := []string{}
	for _, policyName := range policyNames {
		policy := `"` + policyName + `":{
			"Type":"AWS::IoT::Policy",
			"Properties":{
			   "PolicyName":"` + policyName + `"
			}
		 }`
		policiesSection = append(policiesSection, policy)
	}

	thingGroupsStrs := []string{}
	for _, tg := range thingGroups {
		thingGroupsStrs = append(thingGroupsStrs, fmt.Sprintf("\"%s\"", tg))
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
					` + strings.Join(thingGroupsStrs, ",") + `
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

	buffer := new(bytes.Buffer)
	err := json.Compact(buffer, []byte(jitpTemplate))
	if err != nil {
		return "", err
	}
	return buffer.String(), nil
}
