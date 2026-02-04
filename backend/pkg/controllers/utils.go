package controllers

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

func FilterQuery(r *http.Request, filterFieldMap map[string]resources.FilterFieldType) (*resources.QueryParameters, error) {
	queryParams := resources.QueryParameters{
		NextBookmark: "",
		Filters:      []resources.FilterOption{},
		PageSize:     25,
	}

	if len(r.URL.RawQuery) > 0 {
		values := r.URL.Query()
		for k, v := range values {
			switch k {
			case "sort_by":
				value := v[len(v)-1] //only get last
				sortQueryParam := value
				sortField := strings.Trim(sortQueryParam, " ")

				if idx := strings.Index(sortField, "[jsonpath]"); idx != -1 {
					fieldName := sortField[:idx]
					jsonPathExpr := sortField[idx+len("[jsonpath]"):]

					if fieldType, exists := filterFieldMap[fieldName]; exists && fieldType == resources.JsonFilterFieldType {
						// Validate JSONPath expression to prevent SQL injection
						// If invalid, silently ignore the sort parameter (security measure)
						if isValidJsonPath(jsonPathExpr) {
							// Additional check for sorting: Only allow simple dot-separated paths
							// Complex expressions with filters, comparisons, etc. are not supported for sorting
							if isSimpleJsonPath(jsonPathExpr) {
								queryParams.Sort.SortField = fieldName
								queryParams.Sort.JsonPathExpr = jsonPathExpr
							}
						}
					}
				} else {
					_, exists := filterFieldMap[sortField]
					if exists {
						queryParams.Sort.SortField = sortField
					}
				}

			case "sort_mode":
				value := v[len(v)-1] //only get last
				sortQueryParam := value
				sortMode := resources.SortModeAsc

				if sortQueryParam == "desc" {
					sortMode = resources.SortModeDesc
				}

				queryParams.Sort.SortMode = sortMode

			case "page_size":
				value := v[len(v)-1] //only get last
				pageS, err := strconv.Atoi(value)
				if err == nil {
					queryParams.PageSize = pageS
				}

			case "bookmark":
				value := v[len(v)-1] //only get last
				queryParams.NextBookmark = value

			case "filter":
				for _, value := range v {
					filter, err := parseFilterValue(value, filterFieldMap)
					if err != nil {
						return nil, err
					}
					if filter != nil {
						queryParams.Filters = append(queryParams.Filters, *filter)
					}
				}
			}
		}
	}

	return &queryParams, nil
}

// isValidJsonPath validates a JSONPath expression to prevent SQL injection
// Supports PostgreSQL JSONPath syntax including:
// - Simple paths: $.field, $.field.nested
// - Array operations: $[0], $[*], $.array[*], $.array[last]
// - Filters: $.array[*] ? (@ == "value")
// - Comparisons: ==, !=, <, >, <=, >=
// - Logical operators: &&, ||
// - Functions: exists()
// Rejects: SQL keywords, comments, semicolons, and other dangerous patterns
func isValidJsonPath(jsonPath string) bool {
	// JSONPath must start with $
	if !strings.HasPrefix(jsonPath, "$") {
		return false
	}

	// Maximum length to prevent DoS
	if len(jsonPath) > 500 {
		return false
	}

	// Reject SQL keywords and dangerous patterns (case-insensitive)
	dangerousPatterns := []string{
		"--", "/*", "*/", ";",
		"drop ", "delete ", "insert ", "update ", "alter ",
		"create ", "exec", "execute", "union ", "script",
		"<script", "javascript:", "xp_", "sp_",
	}
	lowerPath := strings.ToLower(jsonPath)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	// Allowed characters for PostgreSQL JSONPath:
	// - Alphanumeric, underscore, dot, hyphen
	// - Brackets: [], parentheses: ()
	// - Operators: ?, @, !, =, <, >, &, |, +, -, *, /
	// - Whitespace
	// - Quotes: " (for string literals in filters)
	allowedChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.[]()$?@!=<>&| \t\n\"'-+*/:"
	for _, char := range jsonPath {
		if !strings.ContainsRune(allowedChars, char) {
			return false
		}
	}

	// Additional safety checks:
	// 1. Balanced brackets and parentheses
	bracketCount := 0
	parenCount := 0
	for _, char := range jsonPath {
		switch char {
		case '[':
			bracketCount++
		case ']':
			bracketCount--
		case '(':
			parenCount++
		case ')':
			parenCount--
		}
		// Reject if brackets/parens become negative (closing without opening)
		if bracketCount < 0 || parenCount < 0 {
			return false
		}
	}
	// Final check: all brackets and parens should be balanced
	if bracketCount != 0 || parenCount != 0 {
		return false
	}

	// 2. No excessive consecutive operators to prevent malformed expressions
	if strings.Contains(jsonPath, "...") || strings.Contains(jsonPath, "===") ||
		strings.Contains(jsonPath, "&&&") || strings.Contains(jsonPath, "|||") {
		return false
	}

	return true
}

// isSimpleJsonPath checks if a JSONPath expression is a simple dot-separated path
// suitable for sorting (e.g., $.field, $.field.nested)
// Complex expressions with filters, comparisons, etc. are not supported for sorting
func isSimpleJsonPath(jsonPath string) bool {
	// Must start with $. or $[
	if !strings.HasPrefix(jsonPath, "$.") && !strings.HasPrefix(jsonPath, "$[") {
		return false
	}

	// Remove the $ prefix
	jsonPath = strings.TrimPrefix(jsonPath, "$")

	// Check for characters that indicate complex expressions
	// Simple paths should only contain: letters, numbers, underscore, dot, hyphen, and basic array access
	complexChars := "?@!=<>&|()\" "
	for _, complexChar := range complexChars {
		if strings.ContainsRune(jsonPath, complexChar) {
			return false
		}
	}

	// Allow only simple array access like [0], [1], [last], but not [*] or filters
	if strings.Contains(jsonPath, "[*]") {
		return false
	}

	return true
}

// parseFilterOperand parses a filter operand string and returns the corresponding FilterOperation
// based on the field type. Returns UnspecifiedFilter if the operand is not recognized.
func parseFilterOperand(operand string, fieldType resources.FilterFieldType) resources.FilterOperation {
	operand = strings.ToLower(operand)

	switch fieldType {
	case resources.StringFilterFieldType:
		switch operand {
		case "eq", "equal":
			return resources.StringEqual
		case "eq_ic", "equal_ignorecase":
			return resources.StringEqualIgnoreCase
		case "ne", "notequal":
			return resources.StringNotEqual
		case "ne_ic", "notequal_ignorecase":
			return resources.StringNotEqualIgnoreCase
		case "ct", "contains":
			return resources.StringContains
		case "ct_ic", "contains_ignorecase":
			return resources.StringContainsIgnoreCase
		case "nc", "notcontains":
			return resources.StringNotContains
		case "nc_ic", "notcontains_ignorecase":
			return resources.StringNotContainsIgnoreCase
		}

	case resources.StringArrayFilterFieldType:
		if strings.Contains(operand, "ignorecase") {
			return resources.StringArrayContainsIgnoreCase
		}
		return resources.StringArrayContains

	case resources.DateFilterFieldType:
		switch operand {
		case "bf", "before":
			return resources.DateBefore
		case "eq", "equal":
			return resources.DateEqual
		case "af", "after":
			return resources.DateAfter
		}

	case resources.NumberFilterFieldType:
		switch operand {
		case "eq", "equal":
			return resources.NumberEqual
		case "ne", "notequal":
			return resources.NumberNotEqual
		case "lt", "lessthan":
			return resources.NumberLessThan
		case "le", "lessequal", "lessorequal":
			return resources.NumberLessOrEqualThan
		case "gt", "greaterthan":
			return resources.NumberGreaterThan
		case "ge", "greaterequal", "greaterorequal":
			return resources.NumberGreaterOrEqualThan
		}

	case resources.EnumFilterFieldType:
		switch operand {
		case "eq", "equal":
			return resources.EnumEqual
		case "ne", "notequal":
			return resources.EnumNotEqual
		}

	case resources.JsonFilterFieldType:
		if operand == "jsonpath" {
			return resources.JsonPathExpression
		}
	}

	return resources.UnspecifiedFilter
}

// parseFilterValue parses a single filter value string and returns a FilterOption.
// Returns nil if the filter is invalid or the field doesn't exist in filterFieldMap.
// Returns an error if the filter operand is not recognized for the field type.
func parseFilterValue(value string, filterFieldMap map[string]resources.FilterFieldType) (*resources.FilterOption, error) {
	bs := strings.Index(value, "[")
	es := strings.Index(value, "]")
	if bs == -1 || es == -1 || bs >= es {
		return nil, nil
	}

	field, rest, _ := strings.Cut(value, "[")
	operand, arg, _ := strings.Cut(rest, "]")

	fieldType, exists := filterFieldMap[field]
	if !exists {
		return nil, nil
	}

	filterOperand := parseFilterOperand(operand, fieldType)
	if filterOperand == resources.UnspecifiedFilter {
		return nil, fmt.Errorf("invalid filter operand '%s' for field '%s' of type %v", operand, field, fieldType)
	}

	// Handle URL decoding for JSONPath expressions
	if fieldType == resources.JsonFilterFieldType && filterOperand == resources.JsonPathExpression {
		decodedArg, err := url.QueryUnescape(arg)
		if err == nil {
			arg = decodedArg
		}
	}

	return &resources.FilterOption{
		Field:           field,
		FilterOperation: filterOperand,
		Value:           arg,
	}, nil
}

// FilterQueryWithPrefix parses filter query parameters with a specific key prefix.
// For example, with prefix "ca_filter", it looks for query parameters named "ca_filter"
// instead of the default "filter" parameter name.
func FilterQueryWithPrefix(r *http.Request, filterFieldMap map[string]resources.FilterFieldType, prefix string) (*resources.QueryParameters, error) {
	if len(r.URL.RawQuery) == 0 {
		return nil, nil
	}

	values := r.URL.Query()
	filterValues, exists := values[prefix]
	if !exists || len(filterValues) == 0 {
		return nil, nil
	}

	queryParams := resources.QueryParameters{
		NextBookmark: "",
		Filters:      []resources.FilterOption{},
		PageSize:     25,
	}

	for _, value := range filterValues {
		filter, err := parseFilterValue(value, filterFieldMap)
		if err != nil {
			return nil, err
		}
		if filter != nil {
			queryParams.Filters = append(queryParams.Filters, *filter)
		}
	}

	if len(queryParams.Filters) == 0 {
		return nil, nil
	}

	return &queryParams, nil
// ConvertDeviceGroupCriteria converts API request criteria (with operand names) to model criteria (with FilterOperation enums).
// This strictly validates all criteria fields and operands, returning errors for invalid values.
func ConvertDeviceGroupCriteria(requestCriteria []resources.DeviceGroupFilterOptionRequest, filterFieldMap map[string]resources.FilterFieldType) ([]models.DeviceGroupFilterOption, error) {
	if len(requestCriteria) == 0 {
		return []models.DeviceGroupFilterOption{}, nil
	}

	modelCriteria := make([]models.DeviceGroupFilterOption, 0, len(requestCriteria))

	for i, criteria := range requestCriteria {
		// Strictly validate that the field is allowed
		fieldType, exists := filterFieldMap[criteria.Field]
		if !exists {
			return nil, &InvalidFilterFieldError{Field: criteria.Field, Index: i}
		}

		// Parse the operand name to FilterOperation
		filterOp := resources.ParseOperandName(criteria.Operand, fieldType)
		if filterOp == resources.UnspecifiedFilter {
			return nil, &InvalidOperandError{Field: criteria.Field, Operand: criteria.Operand, FieldType: fieldType, Index: i}
		}

		modelCriteria = append(modelCriteria, models.DeviceGroupFilterOption{
			Field:           criteria.Field,
			FilterOperation: int(filterOp),
			Value:           criteria.Value,
		})
	}

	return modelCriteria, nil
}

// InvalidFilterFieldError indicates that a filter field is not allowed for device filtering.
type InvalidFilterFieldError struct {
	Field string
	Index int
}

func (e *InvalidFilterFieldError) Error() string {
	return "invalid filter field '" + e.Field + "' at criteria index " + strconv.Itoa(e.Index)
}

// InvalidOperandError indicates that an operand is not valid for the given field type.
type InvalidOperandError struct {
	Field     string
	Operand   string
	FieldType resources.FilterFieldType
	Index     int
}

func (e *InvalidOperandError) Error() string {
	return "invalid operand '" + e.Operand + "' for field '" + e.Field + "' at criteria index " + strconv.Itoa(e.Index)
}

// ConvertDeviceGroupToResponse converts a device group model (with FilterOperation integers) to an API response format (with operand names).
// The group model is expected to have all criteria (inherited + own) in the Criteria field.
// This function separates them into inherited_criteria and criteria fields for the API response.
func ConvertDeviceGroupToResponse(group *models.DeviceGroup, ownCriteriaCount int) map[string]interface{} {
	if group == nil {
		return nil
	}

	// Separate inherited criteria from own criteria
	totalCriteria := len(group.Criteria)
	inheritedCount := totalCriteria - ownCriteriaCount
	if inheritedCount < 0 {
		inheritedCount = 0
	}

	// Convert inherited criteria
	inheritedCriteria := make([]resources.DeviceGroupFilterOptionRequest, 0, inheritedCount)
	for i := 0; i < inheritedCount; i++ {
		criterion := group.Criteria[i]
		fieldType, exists := resources.DeviceFilterableFields[criterion.Field]
		if !exists {
			continue
		}
		operand := resources.FormatOperandName(resources.FilterOperation(criterion.FilterOperation), fieldType)
		inheritedCriteria = append(inheritedCriteria, resources.DeviceGroupFilterOptionRequest{
			Field:   criterion.Field,
			Operand: operand,
			Value:   criterion.Value,
		})
	}

	// Convert own criteria
	ownCriteria := make([]resources.DeviceGroupFilterOptionRequest, 0, ownCriteriaCount)
	for i := inheritedCount; i < totalCriteria; i++ {
		criterion := group.Criteria[i]
		fieldType, exists := resources.DeviceFilterableFields[criterion.Field]
		if !exists {
			continue
		}
		operand := resources.FormatOperandName(resources.FilterOperation(criterion.FilterOperation), fieldType)
		ownCriteria = append(ownCriteria, resources.DeviceGroupFilterOptionRequest{
			Field:   criterion.Field,
			Operand: operand,
			Value:   criterion.Value,
		})
	}

	// Build response map with separated criteria
	response := map[string]interface{}{
		"id":                 group.ID,
		"name":               group.Name,
		"description":        group.Description,
		"criteria":           ownCriteria,
		"inherited_criteria": inheritedCriteria,
		"created_at":         group.CreatedAt,
		"updated_at":         group.UpdatedAt,
	}

	// Include parent_id if set
	if group.ParentID != nil {
		response["parent_id"] = *group.ParentID
	}

	return response
}
