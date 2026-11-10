package controllers

import (
	"net/http"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	corequery "github.com/lamassuiot/lamassuiot/v4/core/pkg/query"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
)

func FilterQuery(r *http.Request, filterFieldMap map[string]resources.FilterFieldType) (*resources.QueryParameters, error) {
	return corequery.FilterQuery(r, filterFieldMap)
}

func isValidJsonPath(jsonPath string) bool {
	return corequery.IsValidJSONPath(jsonPath)
}

func isSimpleJsonPath(jsonPath string) bool {
	return corequery.IsSimpleJSONPath(jsonPath)
}

func parseFilterOperand(operand string, fieldType resources.FilterFieldType) resources.FilterOperation {
	return corequery.ParseFilterOperand(operand, fieldType)
}

func parseFilterValue(value string, filterFieldMap map[string]resources.FilterFieldType) (*resources.FilterOption, error) {
	return corequery.ParseFilterValue(value, filterFieldMap)
}

// FilterQueryWithPrefix parses filter query parameters with a specific key prefix.
// For example, with prefix "ca_filter", it looks for query parameters named "ca_filter"
// instead of the default "filter" parameter name.
func FilterQueryWithPrefix(r *http.Request, filterFieldMap map[string]resources.FilterFieldType, prefix string) (*resources.QueryParameters, error) {
	return corequery.FilterQueryWithPrefix(r, filterFieldMap, prefix)
}

// ConvertDeviceGroupCriteria converts API request criteria (with operand names) to model criteria (with FilterOperation enums).
// This strictly validates all criteria fields and operands, returning errors for invalid values.
func ConvertDeviceGroupCriteria(requestCriteria []resources.DeviceGroupFilterOptionRequest, filterFieldMap map[string]resources.FilterFieldType) ([]models.DeviceGroupFilterOption, error) {
	return corequery.ConvertDeviceGroupCriteria(requestCriteria, filterFieldMap)
}

// InvalidFilterFieldError indicates that a filter field is not allowed for device filtering.
type InvalidFilterFieldError = corequery.InvalidFilterFieldError

// InvalidOperandError indicates that an operand is not valid for the given field type.
type InvalidOperandError = corequery.InvalidOperandError

// ConvertDeviceGroupToResponse converts a device group model (with FilterOperation integers) to an API response format (with operand names).
// The group model is expected to have all criteria (inherited + own) in the Criteria field.
// This function separates them into inherited_criteria and criteria fields for the API response.
func ConvertDeviceGroupToResponse(group *models.DeviceGroup, ownCriteriaCount int) map[string]any {
	return corequery.ConvertDeviceGroupToResponse(group, ownCriteriaCount)
}
