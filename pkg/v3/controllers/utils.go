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
				queryParams.Filters = append(queryParams.Filters, resources.FilterOption{})
			}
		}
	}

	return &queryParams
}
