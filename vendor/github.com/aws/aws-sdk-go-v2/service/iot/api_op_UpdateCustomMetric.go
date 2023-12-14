// Code generated by smithy-go-codegen DO NOT EDIT.

package iot

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"time"
)

// Updates a Device Defender detect custom metric. Requires permission to access
// the UpdateCustomMetric (https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiot.html#awsiot-actions-as-permissions)
// action.
func (c *Client) UpdateCustomMetric(ctx context.Context, params *UpdateCustomMetricInput, optFns ...func(*Options)) (*UpdateCustomMetricOutput, error) {
	if params == nil {
		params = &UpdateCustomMetricInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "UpdateCustomMetric", params, optFns, c.addOperationUpdateCustomMetricMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*UpdateCustomMetricOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type UpdateCustomMetricInput struct {

	// Field represents a friendly name in the console for the custom metric, it
	// doesn't have to be unique. Don't use this name as the metric identifier in the
	// device metric report. Can be updated.
	//
	// This member is required.
	DisplayName *string

	// The name of the custom metric. Cannot be updated.
	//
	// This member is required.
	MetricName *string

	noSmithyDocumentSerde
}

type UpdateCustomMetricOutput struct {

	// The creation date of the custom metric in milliseconds since epoch.
	CreationDate *time.Time

	// A friendly name in the console for the custom metric
	DisplayName *string

	// The time the custom metric was last modified in milliseconds since epoch.
	LastModifiedDate *time.Time

	// The Amazon Resource Number (ARN) of the custom metric.
	MetricArn *string

	// The name of the custom metric.
	MetricName *string

	// The type of the custom metric. The type number only takes a single metric value
	// as an input, but while submitting the metrics value in the DeviceMetrics report,
	// it must be passed as an array with a single value.
	MetricType types.CustomMetricType

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationUpdateCustomMetricMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsRestjson1_serializeOpUpdateCustomMetric{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsRestjson1_deserializeOpUpdateCustomMetric{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "UpdateCustomMetric"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
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
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addOpUpdateCustomMetricValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opUpdateCustomMetric(options.Region), middleware.Before); err != nil {
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
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opUpdateCustomMetric(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "UpdateCustomMetric",
	}
}
