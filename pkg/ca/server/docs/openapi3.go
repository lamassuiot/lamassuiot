package docs

import (
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/config"
)

func NewOpenAPI3(config config.Config) openapi3.T {

	arrayOf := func(items *openapi3.SchemaRef) *openapi3.SchemaRef {
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: "array", Items: items}}
	}

	openapiSpec := openapi3.T{
		OpenAPI: "3.0.0",

		Info: &openapi3.Info{
			Title:       "Lamassu CA API",
			Description: "REST API used for interacting with Lamassu CA",
			Version:     "0.0.0",
			License: &openapi3.License{
				Name: "MPL v2.0",
				URL:  "https://github.com/lamassuiot/lamassu-compose/blob/main/LICENSE",
			},
			Contact: &openapi3.Contact{
				URL: "https://github.com/lamassuiot",
			},
		},

		Servers: openapi3.Servers{
			&openapi3.Server{
				Description: "Current Server",
			},
		},
	}

	if config.OpenapiEnableSecuritySchema {
		openapiSpec.Security = *openapi3.NewSecurityRequirements().With(openapi3.NewSecurityRequirement().Authenticate("Keycloak"))
		oidc := openapi3.SecuritySchemeRef{
			Value: openapi3.NewOIDCSecurityScheme(config.OpenapiSecurityOidcWellKnownUrl),
		}
		openapiSpec.Components.SecuritySchemes = openapi3.SecuritySchemes{
			"Keycloak": &oidc,
		}
	}

	openapiSpec.Components.Schemas = openapi3.Schemas{
		"CertificateStatus": openapi3.NewSchemaRef("",
			openapi3.NewStringSchema().
				WithEnum("issued", "expired"),
		),

		"CAType": openapi3.NewSchemaRef("",
			openapi3.NewStringSchema().
				WithEnum("pki", "dmsenroller"),
		),

		"KeyMetadata": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("type", openapi3.NewStringSchema()).
				WithProperty("strength", openapi3.NewStringSchema()).
				WithProperty("bits", openapi3.NewIntegerSchema()),
		),

		"CertificateSubject": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("common_name", openapi3.NewStringSchema()).
				WithProperty("organization", openapi3.NewStringSchema()).
				WithProperty("organization_unit", openapi3.NewStringSchema()).
				WithProperty("country", openapi3.NewStringSchema()).
				WithProperty("state", openapi3.NewStringSchema()).
				WithProperty("locality", openapi3.NewStringSchema()),
		),

		"CertificateContent": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("pem_base64", openapi3.NewStringSchema()).
				WithProperty("public_key_base64", openapi3.NewStringSchema()),
		),

		"LamassuCA": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithPropertyRef("status", &openapi3.SchemaRef{
					Ref: "#/components/schemas/CertificateStatus",
				}).
				WithProperty("serial_number", openapi3.NewStringSchema()).
				WithProperty("name", openapi3.NewStringSchema()).
				WithPropertyRef("key_metadata", &openapi3.SchemaRef{
					Ref: "#/components/schemas/KeyMetadata",
				}).
				WithPropertyRef("subject", &openapi3.SchemaRef{
					Ref: "#/components/schemas/CertificateSubject",
				}).
				WithPropertyRef("certificate", &openapi3.SchemaRef{
					Ref: "#/components/schemas/CertificateContent",
				}).
				WithProperty("ca_ttl", openapi3.NewIntegerSchema()).
				WithProperty("enroller_ttl", openapi3.NewIntegerSchema()).
				WithProperty("valid_from", openapi3.NewStringSchema()).
				WithProperty("valid_to", openapi3.NewStringSchema()),
		),
	}

	openapiSpec.Components.RequestBodies = openapi3.RequestBodies{
		"CreateCARequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Request used for creating a new Certificate Authority").
				WithRequired(true).
				WithJSONSchema(openapi3.NewSchema().
					WithPropertyRef("subject", &openapi3.SchemaRef{
						Ref: "#/components/schemas/CertificateSubject",
					}).
					WithProperty("ca_ttl", openapi3.NewIntegerSchema()).
					WithProperty("enroller_ttl", openapi3.NewIntegerSchema()).
					WithProperty("key_metadata", openapi3.NewObjectSchema().
						WithProperty("type", openapi3.NewStringSchema()).
						WithProperty("bits", openapi3.NewIntegerSchema()),
					),
				),
		},
		"ImportCARequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Request used for importing a Certificate Authority").
				WithRequired(true).
				WithJSONSchema(openapi3.NewSchema().
					WithProperty("enroller_ttl", openapi3.NewIntegerSchema()).
					WithProperty("crt", openapi3.NewStringSchema()).
					WithProperty("private_key", openapi3.NewStringSchema()),
				),
		},
		"SignCertificateRequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Request used for getting all a certificates").
				WithRequired(true).
				WithJSONSchema(openapi3.NewSchema().
					WithProperty("csr", openapi3.NewStringSchema()).
					WithProperty("sign_verbatim", openapi3.NewBoolSchema()),
				),
		},
		"postCSRRequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Request used for getting all a certificates").
				WithRequired(true).
				WithJSONSchema(openapi3.NewSchema().
					WithProperty("csr", openapi3.NewStringSchema()),
				),
		},
	}

	openapiSpec.Components.Responses = openapi3.Responses{
		"ErrorResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response when errors happen.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("error", openapi3.NewStringSchema()))),
		},
		"HealthResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after healthchecking.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("healthy", openapi3.NewBoolSchema())),
				),
		},
		"GetCAResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting a CA.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("total_cas", openapi3.NewIntegerSchema()).
					WithPropertyRef("cas", arrayOf(&openapi3.SchemaRef{
						Ref: "#/components/schemas/LamassuCA",
					}))),
				),
		},
		"CreateCAResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after creating a CA.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/LamassuCA",
				})),
		},
		"RevokeCAResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after revoking a CA.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema())),
		},
		"ImportCAResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after importing a CA.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema())),
		},
		"GetIssuedCertsResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting list of issued certificates.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("total_certs", openapi3.NewIntegerSchema()).
					WithPropertyRef("certs", arrayOf(&openapi3.SchemaRef{
						Ref: "#/components/schemas/LamassuCA",
					}))),
				),
		},
		"GetCertResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting a certificate.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/LamassuCA",
				})),
		},
		"SignCertificateResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after signing certificate.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("crt", openapi3.NewBoolSchema()).
					WithProperty("cacrt", openapi3.NewBoolSchema())),
				),
		},
		"DeleteCertResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after importing a CA.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema())),
		},
	}

	openapiSpec.Paths = openapi3.Paths{
		"/v1/health": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "Health",
				Description: "Get health status",
				Responses: openapi3.Responses{
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/HealthResponse",
					},
				},
			},
		},
		"/v1/{caType}": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetCAs",
				Description: "Get all CAs",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("caType").
							WithSchema(openapi3.NewSchema().
								WithEnum("pki", "dmsenroller"),
							),
					},
					{
						Value: openapi3.NewQueryParameter("filter").
							WithSchema(openapi3.NewStringSchema()).WithRequired(false),
					},
					{
						Value: openapi3.NewQueryParameter("sort_by").
							WithSchema(openapi3.NewStringSchema()).WithRequired(false),
					},
					{
						Value: openapi3.NewQueryParameter("limit").
							WithSchema(openapi3.NewStringSchema()).WithRequired(false),
					},
					{
						Value: openapi3.NewQueryParameter("offset").
							WithSchema(openapi3.NewStringSchema()).WithRequired(false),
					},
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/GetCAResponse",
					},
				},
			},
		},

		"/v1/pki/{caName}": &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "CreateCA",
				Description: "Create new CA using Form",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("caName").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/CreateCARequest",
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/CreateCAResponse",
					},
				},
			},

			Delete: &openapi3.Operation{
				OperationID: "RevokeCA",
				Description: "Revoke CA",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("caName").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/RevokeCAResponse",
					},
				},
			},
		},
		"/v1/pki/import/{caName}": &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "ImportCA",
				Description: "Import existing crt and key",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("caName").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/ImportCARequest",
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/ImportCAResponse",
					},
				},
			},
		},
		"/v1/{caType}/{caName}/issued": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetIssuedCerts",
				Description: "Get Issued certificates by {caName}",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("caName").
							WithSchema(openapi3.NewStringSchema()),
					},
					{
						Value: openapi3.NewPathParameter("caType").
							WithSchema(openapi3.NewSchema().
								WithEnum("pki", "dmsenroller"),
							),
					},
					{
						Value: openapi3.NewQueryParameter("filter").
							WithSchema(openapi3.NewStringSchema()).WithRequired(false),
					},
					{
						Value: openapi3.NewQueryParameter("sort_by").
							WithSchema(openapi3.NewStringSchema()).WithRequired(false),
					},
					{
						Value: openapi3.NewQueryParameter("limit").
							WithSchema(openapi3.NewStringSchema()).WithRequired(false),
					},
					{
						Value: openapi3.NewQueryParameter("offset").
							WithSchema(openapi3.NewStringSchema()).WithRequired(false),
					},
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/GetIssuedCertsResponse",
					},
				},
			},
		},
		"/v1/{caType}/{caName}/cert/{serialNumber}": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetCert",
				Description: "Get certificate by {caName} and {serialNumber}",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("caName").
							WithSchema(openapi3.NewStringSchema()),
					},
					{
						Value: openapi3.NewPathParameter("caType").
							WithSchema(openapi3.NewSchema().
								WithEnum("pki", "dmsenroller"),
							),
					},
					{
						Value: openapi3.NewPathParameter("serialNumber").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/GetCertResponse",
					},
				},
			},
			Delete: &openapi3.Operation{
				OperationID: "DeleteCert",
				Description: "Revoke certificate issued by {caName} and {serialNumber}",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("caName").
							WithSchema(openapi3.NewStringSchema()),
					},
					{
						Value: openapi3.NewPathParameter("caType").
							WithSchema(openapi3.NewSchema().
								WithEnum("pki", "dmsenroller"),
							),
					},
					{
						Value: openapi3.NewPathParameter("serialNumber").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/DeleteCertResponse",
					},
				},
			},
		},
		"/v1/{caType}/{caName}/sign": &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "SignCertificate",
				Description: "Sign CSR by {caName}",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("caName").
							WithSchema(openapi3.NewStringSchema()),
					},
					{
						Value: openapi3.NewPathParameter("caType").
							WithSchema(openapi3.NewSchema().
								WithEnum("pki", "dmsenroller"),
							),
					},
				},
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/SignCertificateRequest",
				},
				Responses: openapi3.Responses{
					"400": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"401": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"403": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"500": &openapi3.ResponseRef{
						Ref: "#/components/responses/ErrorResponse",
					},
					"200": &openapi3.ResponseRef{
						Ref: "#/components/responses/SignCertificateResponse",
					},
				},
			},
		},
	}

	return openapiSpec
}
