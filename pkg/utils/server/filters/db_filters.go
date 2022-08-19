package filters

import (
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common/types"
	"gorm.io/gorm"
)

func ApplyQueryParametersFilters(db *gorm.DB, queryParameters common.QueryParameters) *gorm.DB {
	db = ApplyFilters(db, queryParameters.Filters)
	db = ApplySort(db, queryParameters.Sort)
	db = ApplyPagination(db, queryParameters.Pagination)
	return db
}

func ApplyFilters(db *gorm.DB, filters []types.Filter) *gorm.DB {
	if len(filters) > 0 {
		for _, f := range filters {
			sqlFilter := f.ToSQL()
			if sqlFilter != "" {
				db = db.Where(sqlFilter)
			}
		}
	}
	return db
}

func ApplyPagination(db *gorm.DB, pagination common.PaginationOptions) *gorm.DB {
	if pagination.Limit > 0 {
		db = db.Limit(pagination.Limit)
	}

	if pagination.Offset > 0 {
		db = db.Offset(pagination.Offset)
	}
	return db
}

func ApplySort(db *gorm.DB, sortOptions common.SortOptions) *gorm.DB {
	if sortOptions.SortField != "" {
		if sortOptions.SortMode == common.SortModeAsc || sortOptions.SortMode == common.SortModeDesc {
			db = db.Order(sortOptions.SortField + " " + string(sortOptions.SortMode))
		}
	}
	return db
}
