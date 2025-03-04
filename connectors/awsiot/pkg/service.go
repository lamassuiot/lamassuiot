package pkg

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	hhelpers "github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type AWSCloudConnectorService interface {
	RegisterAndAttachThing(ctx context.Context, input RegisterAndAttachThingInput) error
	UpdateDeviceShadow(ctx context.Context, input UpdateDeviceShadowInput) error
	RegisterCA(ctx context.Context, input RegisterCAInput) (*models.CACertificate, error)
	RegisterGroups(ctx context.Context, input RegisterGroupsInput) error
	RegisterUpdatePolicies(ctx context.Context, input RegisterUpdatePoliciesInput) error
	RegisterUpdateJITPProvisioner(ctx context.Context, input RegisterUpdateJITPProvisionerInput) error
	UpdateCertificateStatus(ctx context.Context, input UpdateCertificateStatusInput) error
	GetRegisteredCAs(ctx context.Context) ([]*models.CACertificate, error)
	GetConnectorID() string
	GetDMSService() services.DMSManagerService
	GetDeviceService() services.DeviceManagerService
	GetCAService() services.CAService
	GetRegion() string
	GetAccountID() string
	GetSQSService() sqs.Client
}

type AWSCloudConnectorServiceBackend struct {
	service         AWSCloudConnectorService
	SqsSDK          sqs.Client
	iotSDK          iot.Client
	Region          string
	iotdataplaneSDK iotdataplane.Client
	logger          *logrus.Entry
	endpointAddress string
	awsCredentials  *aws.Credentials
	ConnectorID     string
	CaSDK           services.CAService
	DmsSDK          services.DMSManagerService
	DeviceSDK       services.DeviceManagerService
	AccountID       string
}

// GetAccountID implements AWSCloudConnectorService.
func (svc *AWSCloudConnectorServiceBackend) GetAccountID() string {
	return svc.AccountID
}

// GetRegion implements AWSCloudConnectorService.
func (svc *AWSCloudConnectorServiceBackend) GetRegion() string {
	return svc.Region
}

// GetSQSService implements AWSCloudConnectorService.
func (svc *AWSCloudConnectorServiceBackend) GetSQSService() sqs.Client {
	return svc.SqsSDK
}

func (svc *AWSCloudConnectorServiceBackend) GetDeviceService() services.DeviceManagerService {
	return svc.DeviceSDK
}

func (svc *AWSCloudConnectorServiceBackend) GetCAService() services.CAService {
	return svc.CaSDK
}

// GetDMSService implements AWSCloudConnectorService.
func (svc *AWSCloudConnectorServiceBackend) GetDMSService() services.DMSManagerService {
	return svc.DmsSDK
}

// GetConnectorID implements AWSCloudConnectorService.
func (svc *AWSCloudConnectorServiceBackend) GetConnectorID() string {
	return svc.ConnectorID
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

func NewAWSCloudConnectorServiceService(builder AWSCloudConnectorBuilder) (AWSCloudConnectorService, error) {
	iotLogger := builder.Logger.WithField("sdk", "AWS IoT Client")
	idpLogger := builder.Logger.WithField("sdk", "AWS IoT Dataplane Client")
	stsLogger := builder.Logger.WithField("sdk", "AWS STS Client")
	sqsLogger := builder.Logger.WithField("sdk", "AWS SQS Client")

	iotHttpCli, err := hhelpers.BuildHTTPClientWithTracerLogger(&http.Client{}, iotLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT http client with tracer: %s", err)
		return nil, err
	}

	idpHttpCli, err := hhelpers.BuildHTTPClientWithTracerLogger(&http.Client{}, idpLogger)
	if err != nil {
		builder.Logger.Errorf("could not build IoT Dataplane http client with tracer: %s", err)
		return nil, err
	}

	stsHttpCli, err := hhelpers.BuildHTTPClientWithTracerLogger(&http.Client{}, stsLogger)
	if err != nil {
		builder.Logger.Errorf("could not build STS http client with tracer: %s", err)
		return nil, err
	}

	sqsHttpCli, err := hhelpers.BuildHTTPClientWithTracerLogger(&http.Client{}, sqsLogger)
	if err != nil {
		builder.Logger.Errorf("could not build SQS http client with tracer: %s", err)
		return nil, err
	}

	iotConf := builder.Conf
	iotConf.HTTPClient = iotHttpCli
	iotClient := iot.NewFromConfig(iotConf)

	awsCreds, err := iotConf.Credentials.Retrieve(context.Background())
	if err != nil {
		builder.Logger.Errorf("could not retrieve AWS credentials: %s", err)
		return nil, err
	}

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

	logger := builder.Logger.WithField("svc", "aws-iot")
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

	svc := &AWSCloudConnectorServiceBackend{
		SqsSDK:          *sqsClient,
		iotSDK:          *iotClient,
		iotdataplaneSDK: *iotdpClient,
		logger:          logger,
		Region:          builder.Conf.Region,
		awsCredentials:  &awsCreds,
		endpointAddress: *endpoint.EndpointAddress,
		AccountID:       *callIDOutput.Account,
		ConnectorID:     builder.ConnectorID,
		CaSDK:           builder.CaSDK,
		DmsSDK:          builder.DmsSDK,
		DeviceSDK:       builder.DeviceSDK,
	}

	svc.service = svc
	return svc, nil
}

type RegisterAndAttachThingInput struct {
	DeviceID               string
	BindedIdentity         models.BindIdentityToDeviceOutput
	DMSIoTAutomationConfig IotAWSDMSMetadata
}

func (svc *AWSCloudConnectorServiceBackend) RegisterAndAttachThing(ctx context.Context, input RegisterAndAttachThingInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := svc.RegisterUpdatePolicies(context.Background(), RegisterUpdatePoliciesInput{
		Policies: input.DMSIoTAutomationConfig.Policies,
	})
	if err != nil {
		lFunc.Errorf("could not register/update policies: %s", err)
		return err
	}

	err = svc.RegisterGroups(context.Background(), RegisterGroupsInput{
		Groups: input.DMSIoTAutomationConfig.GroupNames,
	})
	if err != nil {
		lFunc.Errorf("could not register groups: %s", err)
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
				lFunc.Warnf("error while iterating principals for thing %s: %s", input.DeviceID, err)
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
					lFunc.Warnf("error while revoking AWS certificate-principal %s for thing %s: %s", value, input.DeviceID, err)
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

	ca, err := svc.CaSDK.GetCAByID(context.Background(), services.GetCAByIDInput{
		CAID: input.BindedIdentity.Certificate.IssuerCAMetadata.ID,
	})
	if err != nil {
		lFunc.Errorf("could not get CA %s for device %s: Skipping: %s", input.BindedIdentity.Certificate.IssuerCAMetadata.ID, input.DeviceID, err)
		return err
	}

	params := map[string]string{
		"ThingName":               input.DeviceID,
		"SerialNumber":            helpers.SerialNumberToString(input.BindedIdentity.Certificate.Certificate.SerialNumber),
		"DMS":                     input.BindedIdentity.DMS.ID,
		"LamassuCertificate":      chelpers.CertificateToPEM((*x509.Certificate)(input.BindedIdentity.Certificate.Certificate)),
		"LamassuCACertificatePem": chelpers.CertificateToPEM((*x509.Certificate)(ca.Certificate.Certificate)),
	}

	templateB, err := json.Marshal(template)
	if err != nil {
		lFunc.Errorf("could not serialize template %s", err)
		return err
	}

	registrationOutput, err := svc.iotSDK.RegisterThing(context.Background(), &iot.RegisterThingInput{
		TemplateBody: aws.String(string(templateB)),
		Parameters:   params,
	})
	if err != nil {
		lFunc.Errorf("could not register thing: %s", err)
		return err
	}

	awsCertMetadata := IoTAWSCertificateMetadata{
		ARN: registrationOutput.ResourceArns["certificate"],
	}

	_, err = svc.CaSDK.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: input.BindedIdentity.Certificate.SerialNumber,
		Patches: models.Patch{
			models.PatchOperation{
				Op:    models.OpAdd,
				Path:  "/" + chelpers.EncodePatchKey(AWSIoTMetadataKey(svc.ConnectorID)),
				Value: awsCertMetadata,
			},
		},
	})
	if err != nil {
		lFunc.Errorf("could not update certificate %s metadata: %s", input.BindedIdentity.Certificate.SerialNumber, err)
		return err
	}

	deviceAWSMetadata := DeviceAWSMetadata{
		Registered: true,
		Actions:    []RemediationActionType{},
	}

	_, err = svc.DeviceSDK.UpdateDeviceMetadata(ctx, services.UpdateDeviceMetadataInput{
		ID: input.DeviceID,
		Patches: models.Patch{
			models.PatchOperation{
				Op:    models.OpAdd,
				Path:  "/" + chelpers.EncodePatchKey(AWSIoTMetadataKey(svc.ConnectorID)),
				Value: deviceAWSMetadata,
			},
		},
	})
	if err != nil {
		lFunc.Errorf("could not update device metadata: %s", err)
		return err
	}

	return nil
}

type UpdateCertificateStatusInput struct {
	Certificate models.Certificate
}

func (svc *AWSCloudConnectorServiceBackend) UpdateCertificateStatus(ctx context.Context, input UpdateCertificateStatusInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	var certIoTCoreMeta IoTAWSCertificateMetadata

	hasKey, err := helpers.GetMetadataToStruct(input.Certificate.Metadata, AWSIoTMetadataKey(svc.ConnectorID), &certIoTCoreMeta)
	if err != nil {
		lFunc.Errorf("could not decode metadata with key %s: %s", AWSIoTMetadataKey(svc.ConnectorID), err)
		return err
	}

	if !hasKey {
		lFunc.Warnf("Certificate doesn't have %s key", AWSIoTMetadataKey(svc.ConnectorID))
		return nil
	}

	certIDSplit := strings.Split(certIoTCoreMeta.ARN, "/")
	var status types.CertificateStatus

	switch input.Certificate.Status {
	case models.StatusRevoked:
		if input.Certificate.RevocationReason == ocsp.CertificateHold {
			status = types.CertificateStatusInactive
		} else {
			status = types.CertificateStatusRevoked
		}

		defer func() {
			lFunc.Infof("connecting to IoTCore to force device %s disconnection after cert status update %s", input.Certificate.SerialNumber, status)
			err = svc.connectThingOverMqttWss(ctx, input.Certificate.Certificate.Subject.CommonName)
			if err != nil {
				lFunc.Errorf("could not disconnect device %s over MQTT-WSS: %s", input.Certificate.Certificate.Subject.CommonName, err)
			}
		}()

	case models.StatusActive:
		status = types.CertificateStatusActive
	default:
		lFunc.Warnf("certificate new status (%s - %s) status requires no further action", input.Certificate.SerialNumber, input.Certificate.Status)
		return nil
	}

	_, err = svc.iotSDK.UpdateCertificate(context.Background(), &iot.UpdateCertificateInput{
		CertificateId: aws.String(certIDSplit[1]),
		NewStatus:     status,
	})
	if err != nil {
		lFunc.Warnf("error while updating AWS certificate %s (%s) status to %s: %s", certIDSplit[1], input.Certificate.SerialNumber, status, err)
	}

	return nil
}

type UpdateDeviceShadowInput struct {
	DeviceID               string
	RemediationActionsType []RemediationActionType
	DMSIoTAutomationConfig IotAWSDMSMetadata
}

func (svc *AWSCloudConnectorServiceBackend) UpdateDeviceShadow(ctx context.Context, input UpdateDeviceShadowInput) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	if !input.DMSIoTAutomationConfig.ShadowConfig.Enable {
		lFunc.Warnf("shadow usage is not enabled for DMS associated to device %s. Skipping", input.DeviceID)
		return nil
	}

	getShadowReq := &iotdataplane.GetThingShadowInput{
		ThingName: aws.String(input.DeviceID),
	}
	if input.DMSIoTAutomationConfig.ShadowConfig.ShadowName != "" {
		lFunc.Debugf("using a named shadow with name '%s'", input.DMSIoTAutomationConfig.ShadowConfig.ShadowName)
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

	actionsLogs := []string{}
	processedActions := []RemediationActionType{}
	ts := int(time.Now().UnixMilli())

	for key := range idShadow {
		if slices.Contains(input.RemediationActionsType, RemediationActionType(key)) {
			processedActions = append(processedActions, RemediationActionType(key))
			//action included in input actions. Check if should be added or updated
			//update
			idShadow[key] = ts
			actionsLogs = append(actionsLogs, fmt.Sprintf("%s (updated)", key))
		} else {
			//action not included in input actions. Maintaining it with the same value (timestamp)
			actionsLogs = append(actionsLogs, fmt.Sprintf("%s (retained)", key))
		}
	}

	for _, action := range input.RemediationActionsType {
		//check if action is not already processed
		if !slices.Contains(processedActions, action) {
			//action not processed
			idShadow[string(action)] = ts
			actionsLogs = append(actionsLogs, fmt.Sprintf("%s (added)", action))
			processedActions = append(processedActions, action)
		}
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
		lFunc.Debugf("using a named shadow with name '%s'", input.DMSIoTAutomationConfig.ShadowConfig.ShadowName)
		shadowUpdateMsg.ShadowName = &input.DMSIoTAutomationConfig.ShadowConfig.ShadowName
	}

	_, err = svc.iotdataplaneSDK.UpdateThingShadow(context.Background(), shadowUpdateMsg)
	if err != nil {
		lFunc.Errorf("could not create Update Shadow for thing %s: %s", input.DeviceID, err)
		return err
	}

	actions := []string{}

	for key := range idShadow {
		actions = append(actions, key)
	}

	lFunc.Infof("updated shadow for device %s with remediation actions '%s'", input.DeviceID, strings.Join(actions, ","))

	device, err := svc.DeviceSDK.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: input.DeviceID,
	})
	if err != nil {
		lFunc.Errorf("could not get lamassu device: %s", err)
		return err
	}

	var deviceMetaAWS DeviceAWSMetadata
	hasKey, err := helpers.GetMetadataToStruct(device.Metadata, AWSIoTMetadataKey(svc.ConnectorID), &deviceMetaAWS)
	if err != nil {
		lFunc.Errorf("could not decode metadata with key %s: %s", AWSIoTMetadataKey(svc.ConnectorID), err)
		return err
	}

	if !hasKey {
		lFunc.Warnf("Device doesn't have %s key", AWSIoTMetadataKey(svc.ConnectorID))
		return nil
	}

	deviceMetaAWS.Actions = slices.DeleteFunc(deviceMetaAWS.Actions, func(action RemediationActionType) bool {
		return slices.ContainsFunc(input.RemediationActionsType, func(act RemediationActionType) bool {
			return action == act
		})
	})

	_, err = svc.DeviceSDK.UpdateDeviceMetadata(ctx, services.UpdateDeviceMetadataInput{
		ID: input.DeviceID,
		Patches: models.Patch{
			models.PatchOperation{
				Op:    models.OpAdd,
				Path:  "/" + chelpers.EncodePatchKey(AWSIoTMetadataKey(svc.ConnectorID)) + "/Actions",
				Value: deviceMetaAWS.Actions,
			},
		},
	})
	if err != nil {
		lFunc.Errorf("could not update device metadata: %s", err)
		return err
	}

	device.IdentitySlot.Events[time.Now()] = models.DeviceEvent{
		EvenType:          models.DeviceEventTypeShadowUpdated,
		EventDescriptions: fmt.Sprintf("Remediation Actions: %s", strings.Join(actionsLogs, ", ")),
	}

	_, err = svc.DeviceSDK.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{
		ID:   input.DeviceID,
		Slot: *device.IdentitySlot,
	})
	if err != nil {
		lFunc.Errorf("could not update device metadata: %s", err)
		return err
	}

	return nil
}

func (svc *AWSCloudConnectorServiceBackend) GetRegisteredCAs(ctx context.Context) ([]*models.CACertificate, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

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
			descCrt, err := chelpers.ParseCertificate(*descRes.CertificateDescription.CertificatePem)
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
	RegisterConfiguration IoTAWSCAMetadata
}

func (svc *AWSCloudConnectorServiceBackend) RegisterCA(ctx context.Context, input RegisterCAInput) (ca *models.CACertificate, err error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	defer func() {
		if err != nil {
			//report error in metadata
			lFunc.Infof("updating CA %s metadata with error: %s", input.ID, err)

			input.RegisterConfiguration.Registration.Status = IoTAWSCAMetadataRegistrationFailed
			input.RegisterConfiguration.Registration.Error = fmt.Sprintf("something went wrong while registering CA: %s", err)

			_, err = svc.CaSDK.UpdateCAMetadata(ctx, services.UpdateCAMetadataInput{
				CAID: input.ID,
				Patches: models.Patch{
					models.PatchOperation{
						Op:    models.OpAdd,
						Path:  "/" + chelpers.EncodePatchKey(AWSIoTMetadataKey(svc.GetConnectorID())),
						Value: input.RegisterConfiguration,
					},
				},
			})
			if err != nil {
				lFunc.Errorf("could not update CA metadata: %s", err)
			}
		}
	}()

	//check if CA already registered in AWS
	cas, err := svc.GetRegisteredCAs(context.Background())
	if err != nil {
		lFunc.Errorf("could not get Registered CAs: %s", err)
		return nil, err
	}

	alreadyRegistered := false
	idx := slices.IndexFunc(cas, func(c *models.CACertificate) bool {
		if c.Certificate.SerialNumber == input.Certificate.SerialNumber {
			return true
		} else {
			return false
		}
	})

	if idx != -1 {
		alreadyRegistered = true
	}

	if !alreadyRegistered {
		lFunc.Infof("registering CA with SN '%s'", input.Certificate.SerialNumber)
	} else {
		lFunc.Warnf("CA with SN '%s' is already registered in AWS IoT. Skipping registration process", input.Certificate.SerialNumber)
		return &input.CACertificate, nil
	}

	caCert := input.CACertificate.Certificate.Certificate.String()
	caCertBytes, err := base64.StdEncoding.DecodeString(caCert)
	if err != nil {
		lFunc.Errorf("could not decode b64 CA certificate: %s", err)
		return nil, err
	}

	defer func() {
		if err != nil {
			//report error in metadata
			lFunc.Infof("updating CA %s metadata with error: %s", input.ID, err)
			input.RegisterConfiguration.Registration.Status = IoTAWSCAMetadataRegistrationFailed
			input.RegisterConfiguration.Registration.Error = err.Error()

			_, err = svc.CaSDK.UpdateCAMetadata(ctx, services.UpdateCAMetadataInput{
				CAID: input.ID,
				Patches: models.Patch{
					models.PatchOperation{
						Op:    models.OpAdd,
						Path:  "/" + chelpers.EncodePatchKey(AWSIoTMetadataKey(svc.GetConnectorID())),
						Value: input.RegisterConfiguration,
					},
				},
			})
			if err != nil {
				lFunc.Errorf("could not update CA metadata: %s", err)
			}
		}
	}()

	registerInput := &iot.RegisterCACertificateInput{
		CaCertificate: aws.String(string(caCertBytes)),
		Tags: []types.Tag{
			{
				Key:   aws.String("LMS.CA.ID"),
				Value: &input.ID,
			},
			{
				Key:   aws.String("LMS.CA.SN"),
				Value: &input.Certificate.SerialNumber,
			},
			{
				Key:   aws.String("LMS.CA.CN"),
				Value: &input.Certificate.Subject.CommonName,
			},
		},
		SetAsActive:           true,
		AllowAutoRegistration: true,
	}

	if input.RegisterConfiguration.Registration.PrimaryAccount {
		regCode, err := svc.iotSDK.GetRegistrationCode(context.Background(), &iot.GetRegistrationCodeInput{})
		if err != nil {
			return nil, err
		}

		key, err := chelpers.GenerateRSAKey(2048)
		if err != nil {
			return nil, err
		}

		regCodeCSR, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: *regCode.RegistrationCode}, key)
		if err != nil {
			return nil, err
		}

		csr := models.X509CertificateRequest(*regCodeCSR)

		// Sign verification certificate CSR
		lFunc.Debugf("signing validation csr with cn=%s", csr.Subject.CommonName)
		singOutput, err := svc.CaSDK.SignCertificate(context.Background(), services.SignCertificateInput{
			CAID:        input.CACertificate.ID,
			CertRequest: &csr,
			IssuanceProfile: models.IssuanceProfile{
				SignAsCA:        false,
				Validity:        input.CACertificate.Validity,
				HonorSubject:    true,
				HonorExtensions: true,
			},
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

		registerInput.VerificationCertificate = aws.String(string(validationCertBytes))
	} else {
		lFunc.Debugf("CA %s is not the primary account. Skipping verification certificate registration. Using SNI mode", input.ID)
		registerInput.CertificateMode = types.CertificateModeSniOnly
	}

	lFunc.Debugf("registering id=%s cn=%s CA certificate in AWS", input.ID, input.Certificate.Subject.CommonName)
	regResponse, err := svc.iotSDK.RegisterCACertificate(context.Background(), registerInput)
	if err != nil {
		lFunc.Errorf("something went wrong while registering CA certificate in AWS IoT: %s", err)
		return nil, err
	}

	iotAWSCAMetadata := IoTAWSCAMetadata{
		Account:             svc.AccountID,
		Region:              svc.Region,
		ARN:                 *regResponse.CertificateArn,
		CertificateID:       *regResponse.CertificateId,
		IotCoreMQTTEndpoint: svc.endpointAddress,
		Registration: IoTAWSCAMetadataRegistration{
			RegistrationTime:        time.Now(),
			Status:                  IoTAWSCAMetadataRegistrationSucceeded,
			Error:                   "",
			RegistrationRequestTime: input.RegisterConfiguration.Registration.RegistrationRequestTime,
			PrimaryAccount:          input.RegisterConfiguration.Registration.PrimaryAccount,
		},
	}

	lFunc.Infof("updating CA %s with new metadata: %v\n", input.ID, iotAWSCAMetadata)

	ca, err = svc.CaSDK.UpdateCAMetadata(ctx, services.UpdateCAMetadataInput{
		CAID: input.ID,
		Patches: models.Patch{
			models.PatchOperation{
				Op:    models.OpAdd,
				Path:  "/" + chelpers.EncodePatchKey(AWSIoTMetadataKey(svc.ConnectorID)),
				Value: iotAWSCAMetadata,
			},
		},
	})
	if err != nil {
		lFunc.Errorf("could not update CA metadata: %s", err)
	}

	return ca, nil
}

type RegisterGroupsInput struct {
	Groups []string
}

func (svc *AWSCloudConnectorServiceBackend) RegisterGroups(ctx context.Context, input RegisterGroupsInput) error {
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
	Policies []AWSIoTPolicy
}

func (svc *AWSCloudConnectorServiceBackend) RegisterUpdatePolicies(ctx context.Context, input RegisterUpdatePoliciesInput) error {
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
	AwsJITPConfig IotAWSDMSMetadata
}

func (svc *AWSCloudConnectorServiceBackend) RegisterUpdateJITPProvisioner(ctx context.Context, input RegisterUpdateJITPProvisionerInput) error {
	lFunc := svc.logger

	err := svc.RegisterGroups(ctx, RegisterGroupsInput{
		Groups: input.AwsJITPConfig.GroupNames,
	})
	if err != nil {
		lFunc.Errorf("could not register groups: %s", err)
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
		lFunc.Errorf("could not register/update policies: %s", err)
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
		Enabled:             aws.Bool(input.AwsJITPConfig.JITPProvisioningTemplate.EnableTemplate),
		PreProvisioningHook: nil,
		Tags:                []types.Tag{{Key: aws.String("created-by"), Value: aws.String("LAMASSU")}},
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
	dms.Metadata[AWSIoTMetadataKey(svc.ConnectorID)] = updatedJitpConf

	_, err = svc.DmsSDK.UpdateDMS(ctx, services.UpdateDMSInput{
		DMS: *dms,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while updating DMS metadata: %s", err)
		return err
	}

	return nil
}

type SigV4Utils struct{}

func (s *SigV4Utils) sign(key []byte, msg string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *SigV4Utils) sha256(msg string) string {
	h := sha256.New()
	h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *SigV4Utils) getSignatureKey(key, dateStamp, regionName, serviceName string) []byte {
	hmacSHA256 := func(data string, key []byte) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(data))
		return h.Sum(nil)
	}

	kDate := hmacSHA256(dateStamp, []byte("AWS4"+key))
	kRegion := hmacSHA256(regionName, kDate)
	kService := hmacSHA256(serviceName, kRegion)
	kSigning := hmacSHA256("aws4_request", kService)
	return kSigning
}

func (svc *AWSCloudConnectorServiceBackend) connectThingOverMqttWss(ctx context.Context, thingID string) error {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	time := time.Now().UTC()
	dateStamp := time.Format("20060102")
	amzdate := dateStamp + "T" + time.Format("150405") + "Z"
	service := "iotdevicegateway"
	region := svc.Region
	secretKey := svc.awsCredentials.SecretAccessKey
	accessKey := svc.awsCredentials.AccessKeyID
	algorithm := "AWS4-HMAC-SHA256"
	method := "GET"
	canonicalUri := "/mqtt"
	host := svc.endpointAddress

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	canonicalQuerystring := "X-Amz-Algorithm=AWS4-HMAC-SHA256"
	canonicalQuerystring += "&X-Amz-Credential=" + url.QueryEscape(accessKey+"/"+credentialScope)
	canonicalQuerystring += "&X-Amz-Date=" + amzdate
	canonicalQuerystring += "&X-Amz-Expires=86400"
	canonicalQuerystring += "&X-Amz-SignedHeaders=host"
	canonicalHeaders := "host:" + host + "\n"
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\nhost\n%s", method, canonicalUri, canonicalQuerystring, canonicalHeaders, payloadHash)

	sigV4 := &SigV4Utils{}
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s", algorithm, amzdate, credentialScope, sigV4.sha256(canonicalRequest))
	signingKey := sigV4.getSignatureKey(secretKey, dateStamp, region, service)
	signature := sigV4.sign(signingKey, stringToSign)
	canonicalQuerystring += "&X-Amz-Signature=" + signature

	if svc.awsCredentials.SessionToken != "" {
		canonicalQuerystring += "&X-Amz-Security-Token=" + url.QueryEscape(svc.awsCredentials.SessionToken)
	}

	requestUrl := fmt.Sprintf("wss://%s%s?%s", host, canonicalUri, canonicalQuerystring)
	fmt.Println(requestUrl)

	opts := mqtt.NewClientOptions()
	opts.AddBroker(requestUrl)
	opts.SetClientID(thingID)

	mqttClient := mqtt.NewClient(opts)
	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		return token.Error()
	}

	lFunc.Infof("connected to AWS IoT Core over MQTT-WSS")
	mqttClient.Disconnect(0)
	lFunc.Infof("disconnected from AWS IoT Core over MQTT-WSS")

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
