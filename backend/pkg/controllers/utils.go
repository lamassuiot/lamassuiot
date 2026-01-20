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
