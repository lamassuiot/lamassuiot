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
	SortMode     SortMode
	SortField    string
	JsonPathExpr string // Optional: JSONPath expression for JSON fields
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
	JsonFilterFieldType
)

type FilterOperation int

const (
	UnspecifiedFilter FilterOperation = iota

	StringEqual
	StringEqualIgnoreCase
	StringNotEqual
	StringNotEqualIgnoreCase
	StringContains
	StringContainsIgnoreCase
	StringNotContains
	StringNotContainsIgnoreCase

	StringArrayContains
	StringArrayContainsIgnoreCase

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

	JsonPathExpression
)

type ListInput[E any] struct {
	QueryParameters *QueryParameters
	ExhaustiveRun   bool //wether to iter all elems
	ApplyFunc       func(elem E)
}
