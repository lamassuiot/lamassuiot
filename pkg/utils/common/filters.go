package common

import "github.com/lamassuiot/lamassuiot/pkg/utils/common/types"

type PaginationOptions struct {
	Limit  int
	Offset int
}

type SortMode string

const (
	SortModeAsc  SortMode = "asc"
	SortModeDesc SortMode = "desc"
)

func ParseSortMode(t string) SortMode {
	switch t {
	case "asc":
		return SortModeAsc
	case "desc":
		return SortModeDesc
	}
	return SortModeAsc
}

type SortOptions struct {
	SortMode  SortMode
	SortField string
}

type QueryParameters struct {
	Filters    []types.Filter
	Sort       SortOptions
	Pagination PaginationOptions
}
