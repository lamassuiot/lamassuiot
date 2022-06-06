package filters

import (
	"strconv"
	"strings"
)

func ApplySQLFilter(sqlStatement string, queryParameters QueryParameters) string {
	if len(queryParameters.Filters) > 0 {
		if !strings.Contains(strings.ToLower(sqlStatement), "where") {
			sqlStatement = sqlStatement + " WHERE 1=1 "
		}

		for _, f := range queryParameters.Filters {
			sqlStatement = sqlStatement + " AND " + f.ToSQL()
		}
	}

	if queryParameters.Sort.SortField != "" {
		if strings.ToUpper(queryParameters.Sort.SortMode) == "ASC" || strings.ToUpper(queryParameters.Sort.SortMode) == "DESC" {
			sqlStatement = sqlStatement + "ORDER BY " + queryParameters.Sort.SortField + " " + strings.ToUpper(queryParameters.Sort.SortMode)
		}
	}

	if queryParameters.Pagination.Limit > 0 {
		sqlStatement = sqlStatement + " LIMIT " + strconv.Itoa(queryParameters.Pagination.Limit)
	}

	if queryParameters.Pagination.Offset > 0 {
		sqlStatement = sqlStatement + " OFFSET " + strconv.Itoa(queryParameters.Pagination.Offset)
	}
	return sqlStatement
}
