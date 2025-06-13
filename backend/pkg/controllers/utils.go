package controllers

import (
	"net/http"
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

	if len(r.URL.RawQuery) > 0 {
		values := r.URL.Query()
		for k, v := range values {
			switch k {
			case "sort_by":
				value := v[len(v)-1] //only get last
				sortQueryParam := value
				sortField := strings.Trim(sortQueryParam, " ")

				_, exists := filterFieldMap[sortField]
				if exists {
					queryParams.Sort.SortField = sortField
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
