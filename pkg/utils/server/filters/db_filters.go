package filters

import (
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"gorm.io/gorm"
)

func ApplySQLFilter(db *gorm.DB, queryParameters common.QueryParameters) *gorm.DB {
	if len(queryParameters.Filters) > 0 {
		db = db.Where("1=1")
		for _, f := range queryParameters.Filters {
			db = db.Where(f.ToSQL())
		}
	}

	if queryParameters.Sort.SortField != "" {
		if queryParameters.Sort.SortMode == common.SortModeAsc || queryParameters.Sort.SortMode == common.SortModeDesc {
			db = db.Order(queryParameters.Sort.SortField + " " + string(queryParameters.Sort.SortMode))
		}
	}

	if queryParameters.Pagination.Limit > 0 {
		db = db.Limit(queryParameters.Pagination.Limit)
	}

	if queryParameters.Pagination.Offset > 0 {
		db = db.Offset(queryParameters.Pagination.Offset)
	}

	return db
}
