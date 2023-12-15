package iot

import (
	"bytes"
	"context"
	"crypto/x509"
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
	iotdataplaneTypes "github.com/aws/aws-sdk-go-v2/service/iotdataplane/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

type AWSCloudConnectorService struct {
	SqsSDK          sqs.Client
	iotSDK          iot.Client
	Region          string
	iotdataplaneSDK iotdataplane.Client
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
	State     shadowState `json:"state"`
	Timestamp int         `json:"timestamp"`
	Version   int         `json:"version"`
}

type shadowState struct {
	Reported map[string]any `json:"reported"`
	Desired  map[string]any `json:"desired"`
}

func NewAWSCloudConnectorServiceService(builder AWSCloudConnectorBuilder) (*AWSCloudConnectorService, error) {
	iotLogger := builder.Logger.WithField("sdk", "AWS IoT Client")
	idpLogger := builder.Logger.WithField("sdk", "AWS IoT Dataple Client")
	stsLogger := builder.Logger.WithField("sdk", "AWS STS Client")
	sqsLogger := builder.Logger.WithField("sdk", "AWS SQS Client")

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
		builder.Logger.Errorf("could not build STS http client with tracer: %s", err)
		return nil, err
	}

	sqsHttpCli, err := helpers.BuildHTTPClientWithTracerLogger(&http.Client{}, sqsLogger)
	if err != nil {
		builder.Logger.Errorf("could not build SQS http client with tracer: %s", err)
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

	sqsConf := builder.Conf
	sqsConf.HTTPClient = sqsHttpCli
	sqsClient := sqs.NewFromConfig(sqsConf)

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
		SqsSDK:          *sqsClient,
		iotSDK:          *iotClient,
		iotdataplaneSDK: *iotdpClient,
		logger:          logger,
		Region:          builder.Conf.Region,
		endpointAddress: *endpoint.EndpointAddress,
		AccountID:       *callIDOutput.Account,
		ConnectorID:     builder.ConnectorID,
		CaSDK:           builder.CaSDK,
		DmsSDK:          builder.DmsSDK,
		DeviceSDK:       builder.DeviceSDK,
	}, nil
}

type RegisterAndAttachThingInput struct {
	DeviceID               string
	BindedIdentity         models.BindIdentityToDeviceOutput
	DMSIoTAutomationConfig models.IotAWSDMSMetadata
}

func (svc *AWSCloudConnectorService) RegisterAndAttachThing(input RegisterAndAttachThingInput) error {
	err := svc.RegisterUpdatePolicies(context.Background(), RegisterUpdatePoliciesInput{
		Policies: input.DMSIoTAutomationConfig.Policies,
	})
	if err != nil {
		logrus.Errorf("could not register/update policies: %s", err)
		return err
	}

	err = svc.RegisterGroups(context.Background(), RegisterGroupsInput{
		Groups: input.DMSIoTAutomationConfig.GroupNames,
	})
	if err != nil {
		logrus.Errorf("could not register groups: %s", err)
		return err
	}

	_, err = svc.iotSDK.DescribeThing(context.Background(), &iot.DescribeThingInput{
		ThingName: &input.DeviceID,
	})
	if err == nil {
		//thing was registered, revoke all other attached certs
		paginator := iot.NewListThingPrincipalsPaginator(&svc.iotSDK, &iot.ListThingPrincipalsInput{
			ThingName: &input.DeviceID,
		}, func(ltppo *iot.ListThingPrincipalsPaginatorOptions) {
			ltppo.Limit = 15
		})
		pageNum := 0
		for paginator.HasMorePages() {
			output, err := paginator.NextPage(context.TODO())
			if err != nil {
				logrus.Warnf("error while iterating principals for thing %s: %s", input.DeviceID, err)
			}

			for _, value := range output.Principals {
				//value is an ARN like arn:aws:iot:eu-west-1:XXXXXXX:cert/ea8d99d4fdc37f9a6109614e46183015887cf7366db1bc2b3d62786e5ea0232c
				//get cerID only

				certIDSplit := strings.Split(value, "/")
				_, err = svc.iotSDK.UpdateCertificate(context.Background(), &iot.UpdateCertificateInput{
					CertificateId: aws.String(certIDSplit[1]),
					NewStatus:     types.CertificateStatusRevoked,
				})
				if err != nil {
					logrus.Warnf("error while revoking AWS certificate-principal %s for thing %s: %s", value, input.DeviceID, err)
				}

			}
			pageNum++
		}

	}

	template := map[string]any{
		"Parameters": map[string]any{
			"ThingName": map[string]any{
				"Type": "String",
			},
			"SerialNumber": map[string]any{
				"Type": "String",
			},
			"DMS": map[string]any{
				"Type": "String",
			},
			"LamassuCertificate": map[string]any{
				"Type": "String",
			},
			"LamassuCACertificatePem": map[string]any{
				"Type": "String",
			},
		},
		"Resources": map[string]any{
			"thing": map[string]any{
				"Type": "AWS::IoT::Thing",
				"Properties": map[string]any{
					"ThingName": map[string]any{
						"Ref": "ThingName",
					},
					"AttributePayload": map[string]any{},
					"ThingGroups":      input.DMSIoTAutomationConfig.GroupNames,
				},
				"OverrideSettings": map[string]any{
					"AttributePayload": "REPLACE",
					"ThingTypeName":    "REPLACE",
					"ThingGroups":      "REPLACE",
				},
			},
			"certificate": map[string]any{
				"Type": "AWS::IoT::Certificate",
				"Properties": map[string]any{
					"CACertificatePem": map[string]any{
						"Ref": "LamassuCACertificatePem",
					},
					"CertificatePem": map[string]any{
						"Ref": "LamassuCertificate",
					},
				},
			},
		},
	}

	resources := template["Resources"].(map[string]any)
	for _, policy := range input.DMSIoTAutomationConfig.Policies {
		resources[policy.PolicyName] = map[string]any{
			"Type": "AWS::IoT::Policy",
			"Properties": map[string]any{
				"PolicyName": policy.PolicyName,
			},
		}
	}

	aki := input.BindedIdentity.Certificate.Certificate.AuthorityKeyId
	ca, err := svc.CaSDK.GetCAByID(context.Background(), services.GetCAByIDInput{
		CAID: string(aki),
	})
	if err != nil {
		logrus.Errorf("could not get CA using AKI %s for device %s: Skipping: %s", string(aki), input.DeviceID, err)
		return err
	}

	params := map[string]string{
		"ThingName":               input.DeviceID,
		"SerialNumber":            helpers.SerialNumberToString(input.BindedIdentity.Certificate.Certificate.SerialNumber),
		"DMS":                     input.BindedIdentity.DMS.ID,
		"LamassuCertificate":      helpers.CertificateToPEM((*x509.Certificate)(input.BindedIdentity.Certificate.Certificate)),
		"LamassuCACertificatePem": helpers.CertificateToPEM((*x509.Certificate)(ca.Certificate.Certificate)),
	}

	templateB, err := json.Marshal(template)
	if err != nil {
		logrus.Errorf("could not serialize template %s", err)
		return err
	}

	_, err = svc.iotSDK.RegisterThing(context.Background(), &iot.RegisterThingInput{
		TemplateBody: aws.String(string(templateB)),
		Parameters:   params,
	})
	if err != nil {
		logrus.Errorf("could not register thing: %s", err)
		return err
	}

	device, err := svc.DeviceSDK.GetDeviceByID(services.GetDeviceByIDInput{
		ID: input.DeviceID,
	})
	if err != nil {
		logrus.Errorf("could not get lamassu device: %s", err)
		return err
	}

	device.Metadata[models.AWSIoTMetadataKey(svc.ConnectorID)] = models.DeviceAWSMetadata{
		Registered: true,
		Actions:    []models.RemediationActionType{},
	}

	_, err = svc.DeviceSDK.UpdateDeviceMetadata(services.UpdateDeviceMetadataInput{
		ID:       input.DeviceID,
		Metadata: device.Metadata,
	})
	if err != nil {
		logrus.Errorf("could not update device metadata: %s", err)
		return err
	}

	return nil
}

type UpdateDeviceShadowInput struct {
	DeviceID               string
	RemediationActionsType []models.RemediationActionType
	DMSIoTAutomationConfig models.IotAWSDMSMetadata
}

func (svc *AWSCloudConnectorService) UpdateDeviceShadow(input UpdateDeviceShadowInput) error {
	if !input.DMSIoTAutomationConfig.ShadowConfig.Enable {
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

	deviceShadow := shadowMsg{
		State: shadowState{
			Reported: map[string]any{},
			Desired:  map[string]any{},
		},
		Version: 0,
	}

	var rnf *iotdataplaneTypes.ResourceNotFoundException
	getShadowOutput, err := svc.iotdataplaneSDK.GetThingShadow(context.Background(), getShadowReq)
	if err != nil {
		if !errors.As(err, &rnf) {
			return fmt.Errorf("could not get device %s shadow: %s", input.DeviceID, err)
		}
	} else {
		err = json.Unmarshal(getShadowOutput.Payload, &deviceShadow)
		if err != nil {
			return fmt.Errorf("could not unmarshal device %s shadow: %s", input.DeviceID, err)
		}
	}

	idShadow := map[string]int{}
	//check if shadow has "identity_actions" key
	if idAction, ok := deviceShadow.State.Desired["identity_actions"]; ok {
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

	addedActions := []string{}
	ts := int(time.Now().UnixMilli())
	for _, action := range input.RemediationActionsType {
		idShadow[string(action)] = ts
		addedActions = append(addedActions, string(action))
	}

	deviceShadow.State.Desired["identity_actions"] = idShadow

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

	actions := []string{}

	for key, _ := range idShadow {
		actions = append(actions, key)
	}

	device, err := svc.DeviceSDK.GetDeviceByID(services.GetDeviceByIDInput{
		ID: input.DeviceID,
	})
	if err != nil {
		logrus.Errorf("could not get lamassu device: %s", err)
		return err
	}

	var deviceMetaAWS models.DeviceAWSMetadata
	hasKey, err := helpers.GetMetadataToStruct(device.Metadata, models.AWSIoTMetadataKey(svc.ConnectorID), &deviceMetaAWS)
	if err != nil {
		logrus.Errorf("could not decode metadata with key %s: %s", models.AWSIoTMetadataKey(svc.ConnectorID), err)
		return err
	}

	if !hasKey {
		logrus.Warnf("Device doesn't have %s key", models.AWSIoTMetadataKey(svc.ConnectorID))
		return nil
	}

	deviceMetaAWS.Actions = slices.DeleteFunc(deviceMetaAWS.Actions, func(action models.RemediationActionType) bool {
		return slices.ContainsFunc(input.RemediationActionsType, func(act models.RemediationActionType) bool {
			return action == act
		})
	})

	device.Metadata[models.AWSIoTMetadataKey(svc.ConnectorID)] = deviceMetaAWS

	_, err = svc.DeviceSDK.UpdateDeviceMetadata(services.UpdateDeviceMetadataInput{
		ID:       input.DeviceID,
		Metadata: device.Metadata,
	})
	if err != nil {
		logrus.Errorf("could not update device metadata: %s", err)
		return err
	}

	device.IdentitySlot.Events[time.Now()] = models.DeviceEvent{
		EvenType:          models.DeviceEventTypeShadowUpdated,
		EventDescriptions: fmt.Sprintf("Remediation Actions: %s", strings.Join(addedActions, ", ")),
	}

	_, err = svc.DeviceSDK.UpdateDeviceIdentitySlot(services.UpdateDeviceIdentitySlotInput{
		ID:   input.DeviceID,
		Slot: *device.IdentitySlot,
	})
	if err != nil {
		logrus.Errorf("could not update device metadata: %s", err)
		return err
	}

	logrus.Infof("updated shadow for device %s with remediation actions '%s'", input.DeviceID, strings.Join(actions, ","))
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
			lmsCA, err := svc.CaSDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: string(descCrt.SubjectKeyId)})
			if err != nil {
				lFunc.Warnf("skipping CA with ID AWS '%s' - LAMASSU '%s'. Could not get CA from CA service: %s", *caMeta.CertificateId, string(descCrt.SubjectKeyId), err)
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
		SetAsActive:           true,
		AllowAutoRegistration: true,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while registering CA certificate in AWS IoT: %s", err)
		return nil, err
	}

	newMeta := input.Metadata
	newMeta[models.AWSIoTMetadataKey(svc.ConnectorID)] = models.IoTAWSCAMetadata{
		Account:             svc.AccountID,
		Region:              svc.Region,
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

type RegisterGroupsInput struct {
	Groups []string
}

func (svc *AWSCloudConnectorService) RegisterGroups(ctx context.Context, input RegisterGroupsInput) error {
	var rae *types.ResourceAlreadyExistsException
	_, err := svc.iotSDK.CreateThingGroup(ctx, &iot.CreateThingGroupInput{
		ThingGroupName: aws.String("LAMASSU"),
	})
	if err != nil {
		if !errors.As(err, &rae) {
			return err
		}
	}

	for _, grp := range input.Groups {
		_, err = svc.iotSDK.CreateThingGroup(ctx, &iot.CreateThingGroupInput{
			ThingGroupName:  &grp,
			ParentGroupName: aws.String("LAMASSU"),
		})
		if err != nil {
			if !errors.As(err, &rae) {
				return err
			}
		}
	}

	return nil
}

type RegisterUpdatePoliciesInput struct {
	Policies []models.AWSIoTPolicy
}

func (svc *AWSCloudConnectorService) RegisterUpdatePolicies(ctx context.Context, input RegisterUpdatePoliciesInput) error {
	lFunc := svc.logger
	for _, policy := range input.Policies {
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

	return nil
}

type RegisterUpdateJITPProvisionerInput struct {
	DMS           *models.DMS
	AwsJITPConfig models.IotAWSDMSMetadata
}

func (svc *AWSCloudConnectorService) RegisterUpdateJITPProvisioner(ctx context.Context, input RegisterUpdateJITPProvisionerInput) error {
	lFunc := svc.logger

	err := svc.RegisterGroups(ctx, RegisterGroupsInput{
		Groups: input.AwsJITPConfig.GroupNames,
	})
	if err != nil {
		logrus.Errorf("could not register groups: %s", err)
		return err
	}

	policies := []string{}
	for _, policy := range input.AwsJITPConfig.Policies {
		policies = append(policies, policy.PolicyName)
	}

	err = svc.RegisterUpdatePolicies(context.Background(), RegisterUpdatePoliciesInput{
		Policies: input.AwsJITPConfig.Policies,
	})
	if err != nil {
		logrus.Errorf("could not register/update policies: %s", err)
		return err
	}

	templateBody, err := jitpTemplateBuilder(input.AwsJITPConfig.GroupNames, policies)
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

	jitpTemplate := map[string]any{
		"Parameters": map[string]any{
			"AWS::IoT::Certificate::Country": map[string]any{
				"Type": "String",
			},
			"AWS::IoT::Certificate::Organization": map[string]any{
				"Type": "String",
			},
			"AWS::IoT::Certificate::OrganizationalUnit": map[string]any{
				"Type": "String",
			},
			"AWS::IoT::Certificate::DistinguishedNameQualifier": map[string]any{
				"Type": "String",
			},
			"AWS::IoT::Certificate::StateName": map[string]any{
				"Type": "String",
			},
			"AWS::IoT::Certificate::CommonName": map[string]any{
				"Type": "String",
			},
		},
		"Resources": map[string]any{
			"thing": map[string]any{
				"Type": "AWS::IoT::Thing",
				"Properties": map[string]any{
					"ThingName": map[string]any{
						"Ref": "AWS::IoT::Certificate::CommonName",
					},
					"AttributePayload": map[string]any{},
					"ThingGroups":      thingGroups,
				},
				"OverrideSettings": map[string]any{
					"AttributePayload": "REPLACE",
					"ThingTypeName":    "REPLACE",
					"ThingGroups":      "REPLACE",
				},
			},
			"certificate": map[string]any{
				"Type": "AWS::IoT::Certificate",
				"Properties": map[string]any{
					"CertificateId": map[string]any{
						"Ref": "AWS::IoT::Certificate::Id",
					},
					"Status": "ACTIVE",
				},
			},
		},
	}

	resources := jitpTemplate["Resources"].(map[string]any)
	for _, policyName := range policyNames {
		resources[policyName] = map[string]any{
			"Type": "AWS::IoT::Policy",
			"Properties": map[string]any{
				"PolicyName": policyName,
			},
		}
	}

	b, err := json.Marshal(jitpTemplate)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
