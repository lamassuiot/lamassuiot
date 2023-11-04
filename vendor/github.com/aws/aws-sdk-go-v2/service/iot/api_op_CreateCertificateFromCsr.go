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
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Creates an X.509 certificate using the specified certificate signing request.
// Requires permission to access the CreateCertificateFromCsr (https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiot.html#awsiot-actions-as-permissions)
// action. The CSR must include a public key that is either an RSA key with a
// length of at least 2048 bits or an ECC key from NIST P-256, NIST P-384, or NIST
// P-521 curves. For supported certificates, consult Certificate signing
// algorithms supported by IoT (https://docs.aws.amazon.com/iot/latest/developerguide/x509-client-certs.html#x509-cert-algorithms)
// . Reusing the same certificate signing request (CSR) results in a distinct
// certificate. You can create multiple certificates in a batch by creating a
// directory, copying multiple .csr files into that directory, and then specifying
// that directory on the command line. The following commands show how to create a
// batch of certificates given a batch of CSRs. In the following commands, we
// assume that a set of CSRs are located inside of the directory my-csr-directory:
// On Linux and OS X, the command is: $ ls my-csr-directory/ | xargs -I {} aws
// iot create-certificate-from-csr --certificate-signing-request
// file://my-csr-directory/{} This command lists all of the CSRs in
// my-csr-directory and pipes each CSR file name to the aws iot
// create-certificate-from-csr Amazon Web Services CLI command to create a
// certificate for the corresponding CSR. You can also run the aws iot
// create-certificate-from-csr part of the command in parallel to speed up the
// certificate creation process: $ ls my-csr-directory/ | xargs -P 10 -I {} aws
// iot create-certificate-from-csr --certificate-signing-request
// file://my-csr-directory/{} On Windows PowerShell, the command to create
// certificates for all CSRs in my-csr-directory is: > ls -Name my-csr-directory |
// %{aws iot create-certificate-from-csr --certificate-signing-request
// file://my-csr-directory/$_} On a Windows command prompt, the command to create
// certificates for all CSRs in my-csr-directory is: > forfiles /p
// my-csr-directory /c "cmd /c aws iot create-certificate-from-csr
// --certificate-signing-request file://@path"
func (c *Client) CreateCertificateFromCsr(ctx context.Context, params *CreateCertificateFromCsrInput, optFns ...func(*Options)) (*CreateCertificateFromCsrOutput, error) {
	if params == nil {
		params = &CreateCertificateFromCsrInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CreateCertificateFromCsr", params, optFns, c.addOperationCreateCertificateFromCsrMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CreateCertificateFromCsrOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// The input for the CreateCertificateFromCsr operation.
type CreateCertificateFromCsrInput struct {

	// The certificate signing request (CSR).
	//
	// This member is required.
	CertificateSigningRequest *string

	// Specifies whether the certificate is active.
	SetAsActive bool

	noSmithyDocumentSerde
}

// The output from the CreateCertificateFromCsr operation.
type CreateCertificateFromCsrOutput struct {

	// The Amazon Resource Name (ARN) of the certificate. You can use the ARN as a
	// principal for policy operations.
	CertificateArn *string

	// The ID of the certificate. Certificate management operations only take a
	// certificateId.
	CertificateId *string

	// The certificate data, in PEM format.
	CertificatePem *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCreateCertificateFromCsrMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsRestjson1_serializeOpCreateCertificateFromCsr{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsRestjson1_deserializeOpCreateCertificateFromCsr{}, middleware.After)
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
	if err = addCreateCertificateFromCsrResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addOpCreateCertificateFromCsrValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCreateCertificateFromCsr(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opCreateCertificateFromCsr(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "iot",
		OperationName: "CreateCertificateFromCsr",
	}
}

type opCreateCertificateFromCsrResolveEndpointMiddleware struct {
	EndpointResolver EndpointResolverV2
	BuiltInResolver  builtInParameterResolver
}

func (*opCreateCertificateFromCsrResolveEndpointMiddleware) ID() string {
	return "ResolveEndpointV2"
}

func (m *opCreateCertificateFromCsrResolveEndpointMiddleware) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
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

func addCreateCertificateFromCsrResolveEndpointMiddleware(stack *middleware.Stack, options Options) error {
	return stack.Serialize.Insert(&opCreateCertificateFromCsrResolveEndpointMiddleware{
		EndpointResolver: options.EndpointResolverV2,
		BuiltInResolver: &builtInResolver{
			Region:       options.Region,
			UseDualStack: options.EndpointOptions.UseDualStackEndpoint,
			UseFIPS:      options.EndpointOptions.UseFIPSEndpoint,
			Endpoint:     options.BaseEndpoint,
		},
	}, "ResolveEndpoint", middleware.After)
}
