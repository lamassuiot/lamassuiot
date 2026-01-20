package controllers

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

func FilterQuery(r *http.Request, filterFieldMap map[string]resources.FilterFieldType) *resources.QueryParameters {
	queryParams := resources.QueryParameters{
		NextBookmark: "",
		Filters:      []resources.FilterOption{},
		PageSize:     25,
	}

	var err error

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
							queryParams.Sort.SortField = fieldName
							queryParams.Sort.JsonPathExpr = jsonPathExpr
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
					bs := strings.Index(value, "[")
					es := strings.Index(value, "]")
					if bs != -1 && es != -1 && bs < es {
						field, rest, _ := strings.Cut(value, "[")
						operand, arg, _ := strings.Cut(rest, "]")
						operand = strings.ToLower(operand)

						fieldOperandType, exists := filterFieldMap[field]
						if !exists {
							continue
						}

						var filterOperand resources.FilterOperation
						switch fieldOperandType {
						case resources.StringFilterFieldType:
							switch operand {
							case "eq", "equal":
								filterOperand = resources.StringEqual
							case "eq_ic", "equal_ignorecase":
								filterOperand = resources.StringEqualIgnoreCase
							case "ne", "notequal":
								filterOperand = resources.StringNotEqual
							case "ne_ic", "notequal_ignorecase":
								filterOperand = resources.StringNotEqualIgnoreCase
							case "ct", "contains":
								filterOperand = resources.StringContains
							case "ct_ic", "contains_ignorecase":
								filterOperand = resources.StringContainsIgnoreCase
							case "nc", "notcontains":
								filterOperand = resources.StringNotContains
							case "nc_ic", "notcontains_ignorecase":
								filterOperand = resources.StringNotContainsIgnoreCase
							}

						case resources.StringArrayFilterFieldType:
							if strings.Contains(operand, "ignorecase") {
								filterOperand = resources.StringArrayContainsIgnoreCase
							} else {
								filterOperand = resources.StringArrayContains
							}

						case resources.DateFilterFieldType:
							switch operand {
							case "bf", "before":
								filterOperand = resources.DateBefore
							case "eq", "equal":
								filterOperand = resources.DateEqual
							case "af", "after":
								filterOperand = resources.DateAfter
							}
						case resources.NumberFilterFieldType:
							switch operand {
							case "eq", "equal":
								filterOperand = resources.NumberEqual
							case "ne", "notequal":
								filterOperand = resources.NumberNotEqual
							case "lt", "lessthan":
								filterOperand = resources.NumberLessThan
							case "le", "lessequal", "lessorequal":
								filterOperand = resources.NumberLessOrEqualThan
							case "gt", "greaterthan":
								filterOperand = resources.NumberGreaterThan
							case "ge", "greaterequal", "greaterorequal":
								filterOperand = resources.NumberGreaterOrEqualThan
							}
						case resources.EnumFilterFieldType:
							switch operand {
							case "eq", "equal":
								filterOperand = resources.EnumEqual
							case "ne", "notequal":
								filterOperand = resources.EnumNotEqual
							}
						case resources.JsonFilterFieldType:
							if operand == "jsonpath" {
								filterOperand = resources.JsonPathExpression
								arg, err = url.QueryUnescape(arg)
								if err != nil {
									continue
								}
							}
						default:
							continue
						}
						if exists {
							queryParams.Filters = append(queryParams.Filters, resources.FilterOption{
								Field:           field,
								Value:           arg,
								FilterOperation: filterOperand,
							})
						}
					}

				}
			}
		}
	}

	return &queryParams
}

// isValidJsonPath validates a JSONPath expression to prevent SQL injection
// Allows only: letters, numbers, underscores, dots, and $. prefix
// Rejects: quotes, semicolons, hyphens, parentheses, and other SQL metacharacters
func isValidJsonPath(jsonPath string) bool {
	// JSONPath must start with $. or $[
	if !strings.HasPrefix(jsonPath, "$.") && !strings.HasPrefix(jsonPath, "$[") {
		return false
	}

	// Remove the $. or $[ prefix
	jsonPath = strings.TrimPrefix(jsonPath, "$.")
	jsonPath = strings.TrimPrefix(jsonPath, "$[")

	// Maximum depth to prevent DoS
	if len(jsonPath) > 200 {
		return false
	}

	// Only allow alphanumeric, underscore, and dots
	// This prevents SQL injection via quotes, semicolons, etc.
	for _, char := range jsonPath {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' ||
			char == '.') {
			return false
		}
	}

	// Check for valid structure (no consecutive dots, no leading/trailing dots)
	if strings.Contains(jsonPath, "..") || strings.HasPrefix(jsonPath, ".") || strings.HasSuffix(jsonPath, ".") {
		return false
	}

	return true
}
