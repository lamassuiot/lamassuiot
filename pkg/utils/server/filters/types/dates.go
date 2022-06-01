package types

import (
	"strconv"
	"strings"
	"time"
)

type DateOperatorType int64

const (
	Before DateOperatorType = iota
	After
	Is
	IsNot
)

func ParseDateOperator(s string) DateOperatorType {
	s = strings.ToLower(s)
	switch s {
	case "before":
		return Before
	case "after":
		return After
	case "is":
		return Is
	case "isnot":
		return IsNot
	default:
		return Before
	}
}

func (f DatesFilterField) GetOperatorToString() string {
	switch f.Operator {
	case After:
		return "After"
	case Before:
		return "Before"
	case Is:
		return "Is"
	case IsNot:
		return "IsNot"
	default:
		return ""
	}
}

type DatesFilterField struct {
	baseFilter
	Operator    DateOperatorType
	CompareWith time.Time
}

func (f *DatesFilterField) ToSQL() string {
	compareWithStringValue := f.CompareWith.String()
	switch f.Operator {
	case Is:
		return f.FieldName + " = '" + compareWithStringValue + "' "
	case IsNot:
		return f.FieldName + " <> '" + compareWithStringValue + "' "
	case Before:
		return f.FieldName + " < '" + compareWithStringValue + "' "
	case After:
		return f.FieldName + " > '" + compareWithStringValue + "' "
	default:
		return ""
	}
}

func (f DatesFilterField) GetFieldName() string {
	return f.FieldName
}

func (f DatesFilterField) GetValue() string {
	return strconv.FormatInt(f.CompareWith.Unix(), 10)
}
