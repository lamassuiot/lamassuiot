package controllers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
)

func FilterQuery(r *http.Request) *resources.QueryParameters {
	queryParams := resources.QueryParameters{
		NextBookmark: "",
	}

	if len(r.URL.RawQuery) > 0 {
		values := r.URL.Query()
		for k, v := range values {
			value := v[len(v)-1]
			switch k {
			case "sort_by":
				sortQueryParam := value
				sortField := strings.Trim(sortQueryParam, " ")

				// if _, ok := fieldFiltersMap[sortField]; !ok { //prevent sorting by fields that are not in the filter map
				// 	continue
				// }

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
			}
		}
	}

	return &queryParams
}
