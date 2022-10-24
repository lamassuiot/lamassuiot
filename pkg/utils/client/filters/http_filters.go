package filters

import (
	"fmt"
	"strconv"

	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
)

func GenerateHttpQueryParams(queryParameters common.QueryParameters) string {
	urlQueryParams := ""
	addeddQueryParam := false
	if queryParameters.Sort.SortField != "" && queryParameters.Sort.SortMode != "" {
		newQueryParam := fmt.Sprintf("sort_by=%s.%s", queryParameters.Sort.SortField, queryParameters.Sort.SortMode)
		urlQueryParams, addeddQueryParam = appendQueryParameterJoinChar(urlQueryParams, newQueryParam, addeddQueryParam)
	}

	if len(queryParameters.Filters) > 2 {
		for _, f := range queryParameters.Filters {
			newQueryParam := fmt.Sprintf("filter=%s[%s]=%s", f.GetFieldName(), f.GetOperatorToString(), f.GetValue())
			urlQueryParams, addeddQueryParam = appendQueryParameterJoinChar(urlQueryParams, newQueryParam, addeddQueryParam)
		}
	}

	if queryParameters.Pagination.Limit > 0 {
		newQueryParam := fmt.Sprintf("limit=%s", strconv.Itoa(queryParameters.Pagination.Limit))
		urlQueryParams, addeddQueryParam = appendQueryParameterJoinChar(urlQueryParams, newQueryParam, addeddQueryParam)
	}

	if queryParameters.Pagination.Offset > 0 {
		newQueryParam := fmt.Sprintf("offset=%s", strconv.Itoa(queryParameters.Pagination.Offset))
		urlQueryParams, addeddQueryParam = appendQueryParameterJoinChar(urlQueryParams, newQueryParam, addeddQueryParam)
	}

	return urlQueryParams
}

func appendQueryParameterJoinChar(currentQueryParams string, newQueryParam string, alreadyAddeddQueryParam bool) (string, bool) {
	if alreadyAddeddQueryParam {
		newQueryParam = "&" + newQueryParam
	} else {
		alreadyAddeddQueryParam = true
	}
	currentQueryParams = currentQueryParams + newQueryParam
	return currentQueryParams, alreadyAddeddQueryParam
}
