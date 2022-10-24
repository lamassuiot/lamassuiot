package filters

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common/types"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

func FilterQuery(r *http.Request, fieldFiltersMap map[string]types.Filter) common.QueryParameters {
	queryParams := common.QueryParameters{
		Sort: common.SortOptions{
			SortMode:  common.SortModeAsc,
			SortField: "",
		},
		Pagination: common.PaginationOptions{
			Limit:  100,
			Offset: 0,
		},
		Filters: []types.Filter{},
	}

	if len(r.URL.RawQuery) > 0 {
		values := r.URL.Query()
		for k, v := range values {
			switch k {
			case "filter":
				for _, f := range v {
					f = strings.Trim(f, " ")
					splitFilter := strings.Split(f, "[")
					if len(splitFilter) != 2 {
						continue
					}
					fieldName := strings.Trim(splitFilter[0], " ")
					splitOperators := strings.Split(splitFilter[1], "]=")
					if len(splitOperators) != 2 {
						continue
					}
					operand := strings.Trim(splitOperators[0], " ")
					fieldValue := strings.Trim(splitOperators[1], " ")
					keys := maps.Keys(fieldFiltersMap)
					keyExists := slices.Contains(keys, fieldName)
					if keyExists {
						filter := fieldFiltersMap[fieldName]
						switch castedFilter := filter.(type) {
						case *types.StringFilterField:
							operator := types.ParseStringsOperator(operand)
							castedFilter.FieldName = fieldName
							castedFilter.CompareWith = fieldValue
							castedFilter.Operator = operator
							filter = castedFilter
						case *types.DatesFilterField:
							operator := types.ParseDateOperator(operand)
							secs, err := strconv.ParseInt(fieldValue, 10, 64)
							if err != nil {
								continue
							}
							castedFilter.FieldName = fieldName
							castedFilter.CompareWith = time.UnixMilli(secs)
							castedFilter.Operator = operator
							filter = castedFilter
						case *types.NumberFilterField:
							operator := types.ParseNumberOperator(operand)
							number, err := strconv.Atoi(fieldValue)
							if err != nil {
								continue
							}
							castedFilter.FieldName = fieldName
							castedFilter.CompareWith = number
							castedFilter.Operator = operator
							filter = castedFilter
						}
						queryParams.Filters = append(queryParams.Filters, filter)
					}
				}
			case "sort_by":
				sortQueryParam := v[len(v)-1]
				sortParamsSplit := strings.Split(strings.Trim(sortQueryParam, " "), ".")
				if len(sortParamsSplit) != 2 {
					continue
				}

				sortField := sortParamsSplit[0]
				if _, ok := fieldFiltersMap[sortField]; !ok { //prevent sorting by fields that are not in the filter map
					continue
				}

				sortMode := common.SortModeAsc
				if sortParamsSplit[1] == "desc" {
					sortMode = common.SortModeDesc
				}
				queryParams.Sort.SortMode = sortMode
				queryParams.Sort.SortField = sortField
			case "offset":
				offestQueryParam := v[len(v)-1]
				offestInt, err := strconv.Atoi(offestQueryParam)
				if err != nil {
					continue
				}
				queryParams.Pagination.Offset = offestInt
			case "limit":
				limitQueryParam := v[len(v)-1]
				limitInt, err := strconv.Atoi(limitQueryParam)
				if err != nil {
					continue
				}
				queryParams.Pagination.Limit = limitInt
			default:

			}
		}
	}
	return queryParams
}
