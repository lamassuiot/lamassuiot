package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

func FilterQuery(ctx *gin.Context, r *http.Request, filterFieldMap map[string]resources.FilterFieldType) (*resources.QueryParameters, error) {
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
				value := v[len(v)-1]
				sortField := strings.Trim(value, " ")

				if idx := strings.Index(sortField, "[jsonpath]"); idx != -1 {
					fieldName := sortField[:idx]
					jsonPathExpr := sortField[idx+len("[jsonpath]"):]

					if fieldType, exists := filterFieldMap[fieldName]; exists && fieldType == resources.JsonFilterFieldType {
						if isValidJsonPath(jsonPathExpr) && isSimpleJsonPath(jsonPathExpr) {
							queryParams.Sort.SortField = fieldName
							queryParams.Sort.JsonPathExpr = jsonPathExpr
						}
					}
				} else {
					if _, exists := filterFieldMap[sortField]; exists {
						queryParams.Sort.SortField = sortField
					}
				}

			case "sort_mode":
				value := v[len(v)-1]
				sortMode := resources.SortModeAsc
				if value == "desc" {
					sortMode = resources.SortModeDesc
				}
				queryParams.Sort.SortMode = sortMode

			case "page_size":
				value := v[len(v)-1]
				if pageS, err := strconv.Atoi(value); err == nil {
					queryParams.PageSize = pageS
				}

			case "bookmark":
				queryParams.NextBookmark = v[len(v)-1]

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

func isValidJsonPath(jsonPath string) bool {
	if !strings.HasPrefix(jsonPath, "$") {
		return false
	}
	if len(jsonPath) > 500 {
		return false
	}
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
	allowedChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.[]()$?@!=<>&| \t\n\"'-+*/:"
	for _, char := range jsonPath {
		if !strings.ContainsRune(allowedChars, char) {
			return false
		}
	}
	bracketCount, parenCount := 0, 0
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
		if bracketCount < 0 || parenCount < 0 {
			return false
		}
	}
	if bracketCount != 0 || parenCount != 0 {
		return false
	}
	if strings.Contains(jsonPath, "...") || strings.Contains(jsonPath, "===") ||
		strings.Contains(jsonPath, "&&&") || strings.Contains(jsonPath, "|||") {
		return false
	}
	return true
}

func isSimpleJsonPath(jsonPath string) bool {
	if !strings.HasPrefix(jsonPath, "$.") && !strings.HasPrefix(jsonPath, "$[") {
		return false
	}
	jsonPath = strings.TrimPrefix(jsonPath, "$")
	complexChars := "?@!=<>&|()\" "
	for _, complexChar := range complexChars {
		if strings.ContainsRune(jsonPath, complexChar) {
			return false
		}
	}
	if strings.Contains(jsonPath, "[*]") {
		return false
	}
	return true
}

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
		case "in":
			return resources.StringIn
		case "in_ic":
			return resources.StringInIgnoreCase
		case "nin":
			return resources.StringNotIn
		case "nin_ic":
			return resources.StringNotInIgnoreCase
		}
	case resources.StringArrayFilterFieldType:
		switch operand {
		case "ct_ic", "contains_ignorecase":
			return resources.StringArrayContainsIgnoreCase
		case "ct", "contains":
			return resources.StringArrayContains
		}
		return resources.UnspecifiedFilter
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
		case "in":
			return resources.EnumIn
		}
	case resources.JsonFilterFieldType:
		if operand == "jsonpath" {
			return resources.JsonPathExpression
		}
	}
	return resources.UnspecifiedFilter
}

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

	if fieldType == resources.JsonFilterFieldType && filterOperand == resources.JsonPathExpression {
		if decodedArg, err := url.QueryUnescape(arg); err == nil {
			arg = decodedArg
		}
	}

	return &resources.FilterOption{
		Field:           field,
		FilterOperation: filterOperand,
		Value:           arg,
	}, nil
}
