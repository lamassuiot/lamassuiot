package resources

import "strings"

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

// ParseOperandName converts an operand name string to a FilterOperation enum based on the field type.
// This mirrors the logic in controllers/utils.go FilterQuery function to support consistent operand naming.
func ParseOperandName(operand string, fieldType FilterFieldType) FilterOperation {
	operand = strings.ToLower(operand)

	switch fieldType {
	case StringFilterFieldType:
		switch operand {
		case "eq", "equal":
			return StringEqual
		case "eq_ic", "equal_ignorecase":
			return StringEqualIgnoreCase
		case "ne", "notequal":
			return StringNotEqual
		case "ne_ic", "notequal_ignorecase":
			return StringNotEqualIgnoreCase
		case "ct", "contains":
			return StringContains
		case "ct_ic", "contains_ignorecase":
			return StringContainsIgnoreCase
		case "nc", "notcontains":
			return StringNotContains
		case "nc_ic", "notcontains_ignorecase":
			return StringNotContainsIgnoreCase
		}

	case StringArrayFilterFieldType:
		switch operand {
		case "ct", "contains":
			return StringArrayContains
		case "ct_ic", "contains_ignorecase":
			return StringArrayContainsIgnoreCase
		}

	case DateFilterFieldType:
		switch operand {
		case "bf", "before":
			return DateBefore
		case "eq", "equal":
			return DateEqual
		case "af", "after":
			return DateAfter
		}

	case NumberFilterFieldType:
		switch operand {
		case "eq", "equal":
			return NumberEqual
		case "ne", "notequal":
			return NumberNotEqual
		case "lt", "lessthan":
			return NumberLessThan
		case "le", "lessequal", "lessorequal":
			return NumberLessOrEqualThan
		case "gt", "greaterthan":
			return NumberGreaterThan
		case "ge", "greaterequal", "greaterorequal":
			return NumberGreaterOrEqualThan
		}

	case EnumFilterFieldType:
		switch operand {
		case "eq", "equal":
			return EnumEqual
		case "ne", "notequal":
			return EnumNotEqual
		}

	case JsonFilterFieldType:
		if operand == "jsonpath" {
			return JsonPathExpression
		}
	}

	return UnspecifiedFilter
}
