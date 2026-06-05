package api

import "github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"

var PrincipalFilterableFields = map[string]resources.FilterFieldType{
	"id":          resources.StringFilterFieldType,
	"name":        resources.StringFilterFieldType,
	"description": resources.StringFilterFieldType,
	"type":        resources.EnumFilterFieldType,
	"active":      resources.EnumFilterFieldType,
	"auth_config": resources.JsonFilterFieldType,
	"created_at":  resources.DateFilterFieldType,
	"updated_at":  resources.DateFilterFieldType,
}

var PolicyFilterableFields = map[string]resources.FilterFieldType{
	"id":          resources.StringFilterFieldType,
	"name":        resources.StringFilterFieldType,
	"description": resources.StringFilterFieldType,
	"rules":       resources.JsonFilterFieldType,
	"created_at":  resources.DateFilterFieldType,
	"updated_at":  resources.DateFilterFieldType,
}
