package controllers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
)

func FilterQuery(r *http.Request, filterFieldMap map[string]resources.FilterFieldType) *resources.QueryParameters {
	queryParams := resources.QueryParameters{
		NextBookmark: "",
		Filters:      []resources.FilterOption{},
		PageSize:     25,
	}

	if len(r.URL.RawQuery) > 0 {
		values := r.URL.Query()
		for k, v := range values {
			value := v[len(v)-1]
			switch k {
			case "sort_by":
				sortQueryParam := value
				sortField := strings.Trim(sortQueryParam, " ")

				queryParams.Sort.SortField = sortField

			case "sort_mode":
				sortQueryParam := value
				sortMode := resources.SortModeAsc

				if sortQueryParam == "desc" {
					sortMode = resources.SortModeDesc
				}

				queryParams.Sort.SortMode = sortMode

			case "page_size":
				pageS, err := strconv.Atoi(value)
				if err == nil {
					queryParams.PageSize = pageS
				}

			case "bookmark":
				queryParams.NextBookmark = value

			case "filter":
				//TODO Regex
				bs := strings.Index(value, "[")
				es := strings.Index(value, "]")
				if bs != -1 && es != -1 && bs < es {
					field, rest, _ := strings.Cut(value, "[")
					operand, arg, _ := strings.Cut(rest, "]")
					operand = strings.ToLower(operand)

					fieldOperandType := filterFieldMap[field]
					var filterOperand resources.FilterOperation

					switch fieldOperandType {
					case resources.StringFilterFieldType:
						switch operand {
						case "eq", "equal":
							filterOperand = resources.StringEqual
						case "ne", "notequal":
							filterOperand = resources.StringNotEqual
						case "ct", "contains":
							filterOperand = resources.StringContains
						case "nc", "notcontains":
							filterOperand = resources.StringNotContains
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
					}
					queryParams.Filters = append(queryParams.Filters, resources.FilterOption{
						Field:           field,
						Value:           arg,
						FilterOperation: filterOperand,
					})
				}
			}
		}
	}

	return &queryParams
}
