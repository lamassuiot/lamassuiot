package resources

type PaginationOptions struct {
	NextBookmark string
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

var FilterOperation string
var (
	Equal              = "eq"
	NotEqual           = "ne"
	LessThan           = "lt"
	GreaterThan        = "gt"
	LessThanOrEqual    = "lte"
	GreaterThanOrEqual = "gte"
)

type FilterOption struct {
	Field           string
	FilterOperation string
	Arg             string
}

type QueryParameters struct {
	Sort       SortOptions
	Pagination PaginationOptions
	Filters    []FilterOption
}
