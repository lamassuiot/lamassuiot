// Code generated by smithy-go-codegen DO NOT EDIT.

package iot

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	internalauth "github.com/aws/aws-sdk-go-v2/internal/auth"
	"github.com/aws/aws-sdk-go-v2/service/iot/types"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Creates an IoT OTA update on a target group of things or groups. Requires
// permission to access the CreateOTAUpdate (https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiot.html#awsiot-actions-as-permissions)
// action.
func (c *Client) CreateOTAUpdate(ctx context.Context, params *CreateOTAUpdateInput, optFns ...func(*Options)) (*CreateOTAUpdateOutput, error) {
	if params == nil {
		params = &CreateOTAUpdateInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CreateOTAUpdate", params, optFns, c.addOperationCreateOTAUpdateMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CreateOTAUpdateOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type CreateOTAUpdateInput struct {

	// The files to be streamed by the OTA update.
	//
	// This member is required.
	Files []types.OTAUpdateFile

	// The ID of the OTA update to be created.
	//
	// This member is required.
	OtaUpdateId *string

	// The IAM role that grants Amazon Web Services IoT Core access to the Amazon S3,
	// IoT jobs and Amazon Web Services Code Signing resources to create an OTA update
	// job.
	//
	// This member is required.
	RoleArn *string

	// The devices targeted to receive OTA updates.
	//
	// This member is required.
	Targets []string

	// A list of additional OTA update parameters, which are name-value pairs. They
	// won't be sent to devices as a part of the Job document.
	AdditionalParameters map[string]string

	// The criteria that determine when and how a job abort takes place.
	AwsJobAbortConfig *types.AwsJobAbortConfig

	// Configuration for the rollout of OTA updates.
	AwsJobExecutionsRolloutConfig *types.AwsJobExecutionsRolloutConfig

	// Configuration information for pre-signed URLs.
	AwsJobPresignedUrlConfig *types.AwsJobPresignedUrlConfig

	// Specifies the amount of time each device has to finish its execution of the
	// job. A timer is started when the job execution status is set to IN_PROGRESS . If
	// the job execution status is not set to another terminal state before the timer
	// expires, it will be automatically set to TIMED_OUT .
	AwsJobTimeoutConfig *types.AwsJobTimeoutConfig

	// The description of the OTA update.
	Description *string

	// The protocol used to transfer the OTA update image. Valid values are [HTTP],
	// [MQTT], [HTTP, MQTT]. When both HTTP and MQTT are specified, the target device
	// can choose the protocol.
	Protocols []types.Protocol

	// Metadata which can be used to manage updates.
	Tags []types.Tag

	// Specifies whether the update will continue to run (CONTINUOUS), or will be
	// complete after all the things specified as targets have completed the update
	// (SNAPSHOT). If continuous, the update may also be run on a thing when a change
	// is detected in a target. For example, an update will run on a thing when the
	// thing is added to a target group, even after the update was completed by all
	// things originally in the group. Valid values: CONTINUOUS | SNAPSHOT.
	TargetSelection types.TargetSelection

	noSmithyDocumentSerde
}

type CreateOTAUpdateOutput struct {

	// The IoT job ARN associated with the OTA update.
	AwsIotJobArn *string

	// The IoT job ID associated with the OTA update.
	AwsIotJobId *string

	// The OTA update ARN.
	OtaUpdateArn *string

	// The OTA update ID.
	OtaUpdateId *string

	// The OTA update status.
	OtaUpdateStatus types.OTAUpdateStatus

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCreateOTAUpdateMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsRestjson1_serializeOpCreateOTAUpdate{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsRestjson1_deserializeOpCreateOTAUpdate{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addCreateOTAUpdateResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addOpCreateOTAUpdateValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCreateOTAUpdate(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addendpointDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opCreateOTAUpdate(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "iot",
		OperationName: "CreateOTAUpdate",
	}
}

type opCreateOTAUpdateResolveEndpointMiddleware struct {
	EndpointResolver EndpointResolverV2
	BuiltInResolver  builtInParameterResolver
}

func (*opCreateOTAUpdateResolveEndpointMiddleware) ID() string {
	return "ResolveEndpointV2"
}

func (m *opCreateOTAUpdateResolveEndpointMiddleware) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	if awsmiddleware.GetRequiresLegacyEndpoints(ctx) {
		return next.HandleSerialize(ctx, in)
	}

	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, fmt.Errorf("unknown transport type %T", in.Request)
	}

	if m.EndpointResolver == nil {
		return out, metadata, fmt.Errorf("expected endpoint resolver to not be nil")
	}

	params := EndpointParameters{}

	m.BuiltInResolver.ResolveBuiltIns(&params)

	var resolvedEndpoint smithyendpoints.Endpoint
	resolvedEndpoint, err = m.EndpointResolver.ResolveEndpoint(ctx, params)
	if err != nil {
		return out, metadata, fmt.Errorf("failed to resolve service endpoint, %w", err)
	}

	req.URL = &resolvedEndpoint.URI

	for k := range resolvedEndpoint.Headers {
		req.Header.Set(
			k,
			resolvedEndpoint.Headers.Get(k),
		)
	}

	authSchemes, err := internalauth.GetAuthenticationSchemes(&resolvedEndpoint.Properties)
	if err != nil {
		var nfe *internalauth.NoAuthenticationSchemesFoundError
		if errors.As(err, &nfe) {
			// if no auth scheme is found, default to sigv4
			signingName := "iot"
			signingRegion := m.BuiltInResolver.(*builtInResolver).Region
			ctx = awsmiddleware.SetSigningName(ctx, signingName)
			ctx = awsmiddleware.SetSigningRegion(ctx, signingRegion)

		}
		var ue *internalauth.UnSupportedAuthenticationSchemeSpecifiedError
		if errors.As(err, &ue) {
			return out, metadata, fmt.Errorf(
				"This operation requests signer version(s) %v but the client only supports %v",
				ue.UnsupportedSchemes,
				internalauth.SupportedSchemes,
			)
		}
	}

	for _, authScheme := range authSchemes {
		switch authScheme.(type) {
		case *internalauth.AuthenticationSchemeV4:
			v4Scheme, _ := authScheme.(*internalauth.AuthenticationSchemeV4)
			var signingName, signingRegion string
			if v4Scheme.SigningName == nil {
				signingName = "iot"
			} else {
				signingName = *v4Scheme.SigningName
			}
			if v4Scheme.SigningRegion == nil {
				signingRegion = m.BuiltInResolver.(*builtInResolver).Region
			} else {
				signingRegion = *v4Scheme.SigningRegion
			}
			if v4Scheme.DisableDoubleEncoding != nil {
				// The signer sets an equivalent value at client initialization time.
				// Setting this context value will cause the signer to extract it
				// and override the value set at client initialization time.
				ctx = internalauth.SetDisableDoubleEncoding(ctx, *v4Scheme.DisableDoubleEncoding)
			}
			ctx = awsmiddleware.SetSigningName(ctx, signingName)
			ctx = awsmiddleware.SetSigningRegion(ctx, signingRegion)
			break
		case *internalauth.AuthenticationSchemeV4A:
			v4aScheme, _ := authScheme.(*internalauth.AuthenticationSchemeV4A)
			if v4aScheme.SigningName == nil {
				v4aScheme.SigningName = aws.String("iot")
			}
			if v4aScheme.DisableDoubleEncoding != nil {
				// The signer sets an equivalent value at client initialization time.
				// Setting this context value will cause the signer to extract it
				// and override the value set at client initialization time.
				ctx = internalauth.SetDisableDoubleEncoding(ctx, *v4aScheme.DisableDoubleEncoding)
			}
			ctx = awsmiddleware.SetSigningName(ctx, *v4aScheme.SigningName)
			ctx = awsmiddleware.SetSigningRegion(ctx, v4aScheme.SigningRegionSet[0])
			break
		case *internalauth.AuthenticationSchemeNone:
			break
		}
	}

	return next.HandleSerialize(ctx, in)
}

func addCreateOTAUpdateResolveEndpointMiddleware(stack *middleware.Stack, options Options) error {
	return stack.Serialize.Insert(&opCreateOTAUpdateResolveEndpointMiddleware{
		EndpointResolver: options.EndpointResolverV2,
		BuiltInResolver: &builtInResolver{
			Region:       options.Region,
			UseDualStack: options.EndpointOptions.UseDualStackEndpoint,
			UseFIPS:      options.EndpointOptions.UseFIPSEndpoint,
			Endpoint:     options.BaseEndpoint,
		},
	}, "ResolveEndpoint", middleware.After)
}
