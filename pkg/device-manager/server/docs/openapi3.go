package docs

import (
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/configs"
)

func NewOpenAPI3(config configs.Config) openapi3.T {

	arrayOf := func(items *openapi3.SchemaRef) *openapi3.SchemaRef {
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: "array", Items: items}}
	}

	openapiSpec := openapi3.T{
		OpenAPI: "3.0.0",
		Info: &openapi3.Info{
			Title:       "Lamassu Device Manager API",
			Description: "REST API used for interacting with Lamassu Device Manager",
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
	var consumesRequest []string
	consumesRequest = append(consumesRequest, "application/pkcs10")
	var consumesResponse []string
	consumesResponse = append(consumesResponse, "application/pkcs7-mime; smime-type=certs-only")
	var consumesServerKeyGen []string
	consumesServerKeyGen = append(consumesServerKeyGen, "multipart/mixed; boundary=estServerKeyGenBoundary")

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
		"KeyMetadata": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("type", openapi3.NewStringSchema()).
				WithProperty("strength", openapi3.NewStringSchema()).
				WithProperty("bits", openapi3.NewIntegerSchema()),
		),
		"tags": openapi3.NewSchemaRef("",
			openapi3.NewStringSchema(),
		),
		"CurrentCertificate": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("serial_number", openapi3.NewStringSchema()).
				WithProperty("valid_to", openapi3.NewStringSchema()).
				WithProperty("crt", openapi3.NewStringSchema()),
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
		"EstServer": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("csr", openapi3.NewStringSchema()),
		),

		"Device": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("id", openapi3.NewStringSchema()).
				WithProperty("alias", openapi3.NewStringSchema()).
				WithProperty("status", openapi3.NewStringSchema()).
				WithProperty("dms_id", openapi3.NewIntegerSchema()).
				WithPropertyRef("subject", &openapi3.SchemaRef{
					Ref: "#/components/schemas/Subject",
				}).
				WithPropertyRef("key_metadata", &openapi3.SchemaRef{
					Ref: "#/components/schemas/KeyMetadata",
				}).
				WithProperty("creation_timestamp", openapi3.NewStringSchema()).
				WithProperty("modification_timestamp", openapi3.NewStringSchema()).
				WithPropertyRef("current_certificate", &openapi3.SchemaRef{
					Ref: "#/components/schemas/CurrentCertificate",
				}),
		),
		"DeviceCertHistory": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("device_id", openapi3.NewStringSchema()).
				WithProperty("serial_number", openapi3.NewStringSchema()).
				WithProperty("issuer_name", openapi3.NewStringSchema()).
				WithProperty("status", openapi3.NewStringSchema()).
				WithProperty("creation_timestamp", openapi3.NewStringSchema()),
		),
		"DeviceCert": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("device_id", openapi3.NewStringSchema()).
				WithProperty("serial_number", openapi3.NewStringSchema()).
				WithProperty("issuer_name", openapi3.NewStringSchema()).
				WithProperty("status", openapi3.NewStringSchema()).
				WithProperty("crt", openapi3.NewStringSchema()).
				WithPropertyRef("subject", &openapi3.SchemaRef{
					Ref: "#/components/schemas/Subject",
				}).
				WithProperty("valid_from", openapi3.NewStringSchema()).
				WithProperty("valid_to", openapi3.NewStringSchema()),
		),
		"DeviceLog": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("id", openapi3.NewStringSchema()).
				WithProperty("device_id", openapi3.NewStringSchema()).
				WithProperty("log_type", openapi3.NewStringSchema()).
				WithProperty("log_message", openapi3.NewStringSchema()).
				WithProperty("log_description", openapi3.NewStringSchema()).
				WithProperty("timestamp", openapi3.NewStringSchema()),
		),
		"DmsLastIssued": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("dms_id", openapi3.NewStringSchema()).
				WithProperty("creation_timestamp", openapi3.NewStringSchema()).
				WithProperty("serial_number", openapi3.NewStringSchema()),
		),
		"DmsCertHistory": openapi3.NewSchemaRef("",
			openapi3.NewObjectSchema().
				WithProperty("dms_id", openapi3.NewStringSchema()).
				WithProperty("issued_certs", openapi3.NewStringSchema()),
		),
	}

	openapiSpec.Components.RequestBodies = openapi3.RequestBodies{
		"PostDeviceRequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Request used for creating a new device").
				WithRequired(true).
				WithJSONSchema(openapi3.NewSchema().
					WithProperty("id", openapi3.NewStringSchema()).
					WithProperty("alias", openapi3.NewStringSchema()).
					WithProperty("description", openapi3.NewStringSchema()).
					WithPropertyRef("tags", arrayOf(&openapi3.SchemaRef{
						Ref: "#/components/schemas/tags",
					})).
					WithProperty("icon_name", openapi3.NewStringSchema()).
					WithProperty("icon_color", openapi3.NewStringSchema()).
					WithProperty("dms_id", openapi3.NewStringSchema()),
				),
		},

		"UpdateDeviceRequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Request used for updating").
				WithRequired(true).
				WithJSONSchema(openapi3.NewSchema().
					WithProperty("id", openapi3.NewStringSchema()).
					WithProperty("alias", openapi3.NewStringSchema()).
					WithProperty("description", openapi3.NewStringSchema()).
					WithPropertyRef("tags", arrayOf(&openapi3.SchemaRef{
						Ref: "#/components/schemas/tags",
					})).
					WithProperty("icon_name", openapi3.NewStringSchema()).
					WithProperty("icon_color", openapi3.NewStringSchema()).
					WithProperty("dms_id", openapi3.NewStringSchema()),
				),
		},

		"EnrollRequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Enroll Request").
				WithRequired(true).
				WithContent(openapi3.NewContentWithSchema(openapi3.NewSchema().WithFormat("application/pkcs10"), consumesRequest)),
		},
		"ReenrollRequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Reenroll Request").
				WithRequired(true).
				WithContent(openapi3.NewContentWithSchema(openapi3.NewSchema().WithFormat("application/pkcs10"), consumesRequest)),
		},
		"ServerKeyGenRequest": &openapi3.RequestBodyRef{
			Value: openapi3.NewRequestBody().
				WithDescription("Server Key Gen Request").
				WithRequired(true).
				WithContent(openapi3.NewContentWithSchema(openapi3.NewSchema().WithFormat("application/pkcs10"), consumesRequest)),
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
		"DeviceResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after creating a device.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("id", openapi3.NewStringSchema()).
					WithProperty("alias", openapi3.NewStringSchema()).
					WithProperty("description", openapi3.NewStringSchema()).
					WithPropertyRef("tags", arrayOf(&openapi3.SchemaRef{
						Ref: "#/components/schemas/tags",
					})).
					WithProperty("icon_name", openapi3.NewStringSchema()).
					WithProperty("icon_color", openapi3.NewStringSchema()).
					WithProperty("dms_id", openapi3.NewStringSchema()),
				)),
		},
		"GetDeviceResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after creating a device.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("total_devices", openapi3.NewIntegerSchema()).
					WithPropertyRef("devices", arrayOf(&openapi3.SchemaRef{
						Ref: "#/components/schemas/Device",
					})),
				)),
		},
		"GetDevicebyIDResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after creating a device.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/Device",
				})),
		},
		"DeleteRevokeResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after revoking a device.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema())),
		},
		"GetDeviceLogsResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting logs of a device.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("total_logs", openapi3.NewIntegerSchema()).
					WithPropertyRef("devices", arrayOf(&openapi3.SchemaRef{
						Ref: "#/components/schemas/DeviceLog",
					})),
				)),
		},
		"GetDeviceCertResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting certificate of a device.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/DeviceCert",
				})),
		},
		"GetDeviceCertHistoryResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting certificate history of a device.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(&openapi3.SchemaRef{
					Ref: "#/components/schemas/DeviceCertHistory",
				})),
		},
		"GetDmsLastIssueCertResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting last iisued certificate of a device.").
				WithContent(openapi3.NewContentWithJSONSchema(openapi3.NewSchema().
					WithProperty("total_last_issued_cert", openapi3.NewIntegerSchema()).
					WithPropertyRef("dms_last_issued_cert", arrayOf(&openapi3.SchemaRef{
						Ref: "#/components/schemas/DmsLastIssued",
					})),
				)),
		},
		"GetDmsCertHistoryResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response returned back after getting last iisued certificate of a device.").
				WithContent(openapi3.NewContentWithJSONSchemaRef(arrayOf(&openapi3.SchemaRef{
					Ref: "#/components/schemas/DmsCertHistory",
				})),
				),
		},
		"EnrollResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response Enroll").
				WithContent(openapi3.NewContentWithSchema(openapi3.NewSchema().WithFormat(consumesResponse[0]), consumesResponse)),
		},
		"ReenrollResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response Reenroll").
				WithContent(openapi3.NewContentWithSchema(openapi3.NewSchema().WithFormat(consumesResponse[0]), consumesResponse)),
		},
		"cacertsResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Response CACerts").
				WithContent(openapi3.NewContentWithSchema(openapi3.NewSchema().WithFormat(consumesResponse[0]), consumesResponse)),
		},
		"ServerKeyGenResponse": &openapi3.ResponseRef{
			Value: openapi3.NewResponse().
				WithDescription("Server Key Gen Response").
				WithContent(openapi3.NewContentWithSchema(openapi3.NewSchema().WithFormat(consumesServerKeyGen[0]), consumesServerKeyGen)),
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
		"/v1/devices?": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDevices",
				Description: "Get Devices",
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
						Ref: "#/components/responses/GetDeviceResponse",
					},
				},
			},
		},
		"/v1/devices": &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "PostDevice",
				Description: "Post Device",
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/PostDeviceRequest",
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
						Ref: "#/components/responses/DeviceResponse",
					},
				},
			},
		},

		"/v1/devices/{deviceId}": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDeviceById",
				Description: "Get Device By Id",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
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
						Ref: "#/components/responses/GetDevicebyIDResponse",
					},
				},
			},
			Put: &openapi3.Operation{
				OperationID: "UpdateDeviceById",
				Description: "Update Device By Id",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
							WithSchema(openapi3.NewStringSchema()),
					},
				},
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/UpdateDeviceRequest",
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
						Ref: "#/components/responses/GetDeviceResponse",
					},
				},
			},
			Delete: &openapi3.Operation{
				OperationID: "DeleteDevice",
				Description: "Delete Device By Id",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
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
						//TODO:
						Ref: "#/components/responses/StringResponse",
					},
				},
			},
		},

		"/v1/devices/{deviceId}/revoke": &openapi3.PathItem{
			Delete: &openapi3.Operation{
				OperationID: "DeleteRevoke",
				Description: "Delete Revoke device by Id",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
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
						Ref: "#/components/responses/DeleteRevokeResponse",
					},
				},
			},
		},
		"/v1/devices/{deviceId}/logs?": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDeviceLogs",
				Description: "Get Device Logs of deviceId",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
							WithSchema(openapi3.NewStringSchema()),
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
						Ref: "#/components/responses/GetDeviceLogsResponse",
					},
				},
			},
		},
		"/v1/devices/{deviceId}/cert": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDeviceCert",
				Description: "Get Device Cert of deviceId",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
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
						Ref: "#/components/responses/GetDeviceCertResponse",
					},
				},
			},
		},
		"/v1/devices/{deviceId}/cert-history": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDeviceCertHistory",
				Description: "Get Device Cert History of deviceId",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("deviceId").
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
						Ref: "#/components/responses/GetDeviceCertHistoryResponse",
					},
				},
			},
		},
		"/v1/devices/dms/{dmsId}?": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDevicesByDmsId",
				Description: "Get Devices By DMS Id",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("dmsId").
							WithSchema(openapi3.NewStringSchema()),
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
						Ref: "#/components/responses/GetDeviceResponse",
					},
				},
			},
		},
		"/v1/devices/dms-cert-history/thirty-days?": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDmsCertHistoryThirtyDays",
				Description: "Get Dms Cert History of last Thirty Days",
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
						Ref: "#/components/responses/GetDmsCertHistoryResponse",
					},
				},
			},
		},
		"/v1/devices/dms-cert-history/last-issued?": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "GetDmsLastIssueCert",
				Description: "Get Dms Cert History of last Thirty Days",
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
						Ref: "#/components/responses/GetDmsLastIssueCertResponse",
					},
				},
			},
		},
		"/.well-known/est/{aps}/simpleenroll": &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "Enroll",
				Description: "Enrool Device",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("aps").
							WithSchema(openapi3.NewStringSchema()),
					},
					{
						Value: openapi3.NewHeaderParameter("Content-Transfer-Encoding").
							WithSchema(openapi3.NewStringSchema().WithEnum("base64")),
					},
					{
						Value: openapi3.NewHeaderParameter("Accept").
							WithSchema(openapi3.NewStringSchema().WithEnum("application/pkcs7-mime")),
					},
				},
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/EnrollRequest",
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
						Ref: "#/components/responses/EnrollResponse",
					},
				},
			},
		},
		"/.well-known/est/cacerts": &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: "CACerts",
				Description: "CACerts",
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
						Ref: "#/components/responses/cacertsResponse",
					},
				},
			},
		},
		"/.well-known/est/simplereenroll": &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "Reenroll",
				Description: "Reenroll Device",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewHeaderParameter("Content-Transfer-Encoding").
							WithSchema(openapi3.NewStringSchema().WithEnum("base64")),
					},
					{
						Value: openapi3.NewHeaderParameter("Accept").
							WithSchema(openapi3.NewStringSchema().WithEnum("application/pkcs7-mime")),
					},
				},
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/ReenrollRequest",
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
						Ref: "#/components/responses/ReenrollResponse",
					},
				},
			},
		},
		"/.well-known/est/{aps}/serverkeygen": &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: "Server Key Generation",
				Description: "Server Key Generation",
				Parameters: []*openapi3.ParameterRef{
					{
						Value: openapi3.NewPathParameter("aps").
							WithSchema(openapi3.NewStringSchema()),
					},
					{
						Value: openapi3.NewHeaderParameter("Content-Transfer-Encoding").
							WithSchema(openapi3.NewStringSchema().WithEnum("base64")),
					},
					{
						Value: openapi3.NewHeaderParameter("Accept").
							WithSchema(openapi3.NewStringSchema().WithEnum("multipart/mixed")),
					},
				},
				RequestBody: &openapi3.RequestBodyRef{
					Ref: "#/components/requestBodies/ServerKeyGenRequest",
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
						Ref: "#/components/responses/ServerKeyGenResponse",
					},
				},
			},
		},
	}

	return openapiSpec
}
