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

var PrincipalPolicyFilterableFields = map[string]resources.FilterFieldType{
	"policy_id":  resources.StringFilterFieldType,
	"granted_at": resources.DateFilterFieldType,
	"granted_by": resources.StringFilterFieldType,
}

var PolicyFilterableFields = map[string]resources.FilterFieldType{
	"id":          resources.StringFilterFieldType,
	"name":        resources.StringFilterFieldType,
	"description": resources.StringFilterFieldType,
	"rules":       resources.JsonFilterFieldType,
	"created_at":  resources.DateFilterFieldType,
	"updated_at":  resources.DateFilterFieldType,
}
