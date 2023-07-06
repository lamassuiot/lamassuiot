package types

import (
	"strconv"
	"strings"
	"time"
)

type DateOperatorType string

const (
	Before DateOperatorType = "before"
	After  DateOperatorType = "after"
	Is     DateOperatorType = "is"
	IsNot  DateOperatorType = "isnot"
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
	return string(f.Operator)
}

type DatesFilterField struct {
	BaseFilter
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
	return strconv.FormatInt(f.CompareWith.UnixMilli(), 10)
}
