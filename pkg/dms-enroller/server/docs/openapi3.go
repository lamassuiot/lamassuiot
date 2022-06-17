package docs

import (
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/config"
)

func NewOpenAPI3(config config.Config) openapi3.T {

	arrayOf := func(items *openapi3.SchemaRef) *openapi3.SchemaRef {
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: "array", Items: items}}
	}

	openapiSpec := openapi3.T{
		OpenAPI: "3.0.0",
		Info: &openapi3.Info{
			Title:       "Lamassu DMS Enroller API",
			Description: "REST API used for interacting with Lamassu DMS Enroller",
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
				URL:         "/",
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
		"DMS": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("id", openapi3.NewIntegerSchema()).
				WithProperty("name", openapi3.NewStringSchema()).
				WithProperty("serial_number", openapi3.NewStringSchema()).
				WithPropertyRef("subject", &openapi3.SchemaRef{
					Ref: "#/components/schemas/Subject",
				}).
				WithPropertyRef("key_metadata", &openapi3.SchemaRef{
					Ref: "#/components/schemas/KeyMetadata",
				}).
				WithProperty("status", openapi3.NewStringSchema()).
				WithPropertyRef("authorized_cas", arrayOf(&openapi3.SchemaRef{
					Ref: "#/components/schemas/CAList",
				})).
				WithProperty("csr", openapi3.NewStringSchema()).
				WithProperty("crt", openapi3.NewStringSchema()).
				WithProperty("creation_timestamp", openapi3.NewStringSchema()).
				WithProperty("modification_timestamp", openapi3.NewStringSchema()),
		),
		"Subject": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("common_name", openapi3.NewStringSchema()).
				WithProperty("organization", openapi3.NewStringSchema()).
				WithProperty("organization_unit", openapi3.NewStringSchema()).
				WithProperty("country", openapi3.NewStringSchema()).
				WithProperty("state", openapi3.NewStringSchema()).
				WithProperty("locality", openapi3.NewStringSchema()),
		),
		"CAList": openapi3.NewSchemaRef("",
			openapi3.NewStringSchema(),
		),
		"KeyMetadata": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("type", openapi3.NewStringSchema()).
				WithProperty("bits", openapi3.NewIntegerSchema()),
		),
	}

	openapiSpec.Components.RequestBodies = openapi3.RequestBodies{
		"postDMSRequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Request used for creating a new DMS ").
				WithRequired(true).
				WithJSONSchema(openapi3.NewSchema().
					WithProperty("csr", openapi3.NewStringSchema()).
					WithProperty("name", openapi3.NewStringSchema()),
				),
		},
		"postDMSFormRequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Request used for creating a new DMS Form").
				WithRequired(true).
				WithJSONSchema(openapi3.NewSchema().
					WithProperty("name", openapi3.NewStringSchema()).
					WithPropertyRef("subject", &openapi3.SchemaRef{
						Ref: "#/components/schemas/Subject",
					}).
					WithPropertyRef("key_metadata", &openapi3.SchemaRef{
						Ref: "#/components/schemas/KeyMetadata",
					}),
				),
		},
		"getPendingCSRRequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Request used for creating a new CSR Form").
				WithRequired(true).
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("ID", openapi3.NewIntegerSchema()))),
		},
		"PutChangeDMSStatus": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Change DMS status ").
				WithRequired(true).
				WithJSONSchema(openapi3.NewSchema().
					WithProperty("status", openapi3.NewStringSchema()).
					WithPropertyRef("authorized_cas", arrayOf(&openapi3.SchemaRef{
						Ref: "#/components/schemas/CAList",
					}))),
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
		"PostDMSResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after creating a DMS.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/DMS",
				})),
		},
		"PostDMSFormResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after creating a DMS.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithPropertyRef("dms", &openapi3.SchemaRef{
						Ref: "#/components/schemas/DMS",
					}).
					WithProperty("priv_key", openapi3.NewStringSchema())),
				),
		},
		"GetPendingDMSsResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting pending CSRs.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("total_dmss", openapi3.NewIntegerSchema()).
					WithPropertyRef("dmss", arrayOf(&openapi3.SchemaRef{
						Ref: "#/components/schemas/DMS",
					}))),
				),
		},
		"GetDMSByIDResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting pending CSRs.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/DMS",
				})),
		},
		"PutChangeDMSStatusResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after changing DMS Status.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/DMS",
				})),
		},
		"DeleteDMSResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after deleting DMS.").
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
		"/v1/{name}": &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "PostDMS",
				Description: "Post DMS",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("name").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/postDMSRequest",
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
						Ref: "#/components/responses/PostDMSResponse",
					},
				},
			},
		},
		"/v1/{name}/form": &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "PostDMSForm",
				Description: "Post DMS Form",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("name").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/postDMSFormRequest",
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
						Ref: "#/components/responses/PostDMSFormResponse",
					},
				},
			},
		},
		"/v1/": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDMSs",
				Description: "Get DMSs",
				Parameters: []*openapi3.ParameterRef{
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
						Ref: "#/components/responses/GetPendingDMSsResponse",
					},
				},
			},
		},

		"/v1/{id}": &openapi3.PathItem{
			Put: &openapi3.Operation{
				OperationID: "PutChangeDMSStatus",
				Description: "Change DMS Status by id",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("id").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/PutChangeDMSStatus",
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
						Ref: "#/components/responses/PutChangeDMSStatusResponse",
					},
				},
			},
			Get: &openapi3.Operation{
				OperationID: "GetDMSbyID",
				Description: "Get DMS by ID",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("id").
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
						Ref: "#/components/responses/GetDMSByIDResponse",
					},
				},
			},
			Delete: &openapi3.Operation{
				OperationID: "DeleteDMS",
				Description: "Delete DMS by id",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("id").
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
						Ref: "#/components/responses/DeleteDMSResponse",
					},
				},
			},
		},
	}

	return openapiSpec
}
