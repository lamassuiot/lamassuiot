package resources

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

type FilterOption struct {
	Field           string
	FilterOperation FilterOperation
	Value           string
}

type QueryParameters struct {
	NextBookmark string
	Sort         SortOptions
	PageSize     int
	Filters      []FilterOption
}

type FilterFieldType int

const (
	StringFilterFieldType FilterFieldType = iota
	StringArrayFilterFieldType
	DateFilterFieldType
	NumberFilterFieldType
	EnumFilterFieldType
)

type FilterOperation int

const (
	UnspecifiedFilter FilterOperation = iota

	StringEqual
	StringNotEqual
	StringContains
	StringNotContains

	StringArrayContains

	DateEqual
	DateBefore
	DateAfter

	NumberEqual
	NumberNotEqual
	NumberLessThan
	NumberLessOrEqualThan
	NumberGreaterThan
	NumberGreaterOrEqualThan

	EnumEqual
	EnumNotEqual
)
