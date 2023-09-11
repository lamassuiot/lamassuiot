package controllers

import (
	"encoding/base64"
	"net/http"
	"strconv"
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
			PageSize:     15,
			Offset:       0,
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
			case "page_size":
				pageS, err := strconv.Atoi(v[len(v)-1])
				if err == nil {
					queryParams.Pagination.PageSize = pageS
				}

			case "c29ydF9ieQ==": //sort_by
				sortFieldbytes, err := base64.StdEncoding.DecodeString(v[len(v)-1])
				if err == nil {
					sortFieldParam := string(sortFieldbytes)
					queryParams.Sort.SortField = sortFieldParam
				}

			case "c29ydF9tb2Rl": //sort_mode
				var sortModeParam resources.SortMode
				sortModebytes, err := base64.StdEncoding.DecodeString(v[len(v)-1])
				if err == nil {
					sortModeParam = resources.ParseSortMode(string(sortModebytes))
					queryParams.Sort.SortMode = sortModeParam
				}
			case "bGltaXQ=": //limit
				limitBytes, err := base64.StdEncoding.DecodeString(v[len(v)-1])
				if err == nil {
					limitParam := string(limitBytes)
					limitInt, err := strconv.Atoi(limitParam)
					if err == nil {
						queryParams.Pagination.PageSize = limitInt
					}
				}
			case "b2Zmc2V0": //offset
				offsetBytes, err := base64.StdEncoding.DecodeString(v[len(v)-1])
				if err == nil {
					offsetParam := string(offsetBytes)
					offsetInt, err := strconv.Atoi(offsetParam)
					if err == nil {
						queryParams.Pagination.Offset = offsetInt
					}
				}

			default:

			}
		}
	}

	return &queryParams
}
