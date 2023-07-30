package controllers

import (
	"net/http"
	"strings"

	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
)

func FilterQuery(r *http.Request) *resources.QueryParameters {
	queryParams := resources.QueryParameters{
		Sort: resources.SortOptions{
			SortMode:  resources.SortModeAsc,
			SortField: "",
		},
		Pagination: resources.PaginationOptions{
			NextBookmark: "",
		},
	}

	if len(r.URL.RawQuery) > 0 {
		values := r.URL.Query()
		for k, v := range values {
			switch k {
			case "sort_by":
				sortQueryParam := v[len(v)-1]
				sortField := strings.Trim(sortQueryParam, " ")

				// if _, ok := fieldFiltersMap[sortField]; !ok { //prevent sorting by fields that are not in the filter map
				// 	continue
				// }

				queryParams.Sort.SortField = sortField
			case "sort_mode":
				sortQueryParam := v[len(v)-1]
				sortMode := resources.SortModeAsc

				if sortQueryParam == "desc" {
					sortMode = resources.SortModeDesc
				}

				queryParams.Sort.SortMode = sortMode
			case "bookmark":
				offestQueryParam := v[len(v)-1]
				queryParams.Pagination.NextBookmark = offestQueryParam
			default:

			}
		}
	}
	return &queryParams
}
