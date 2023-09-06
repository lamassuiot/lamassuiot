package types

import "strings"

type StringOperatorType string

const (
	Equals      StringOperatorType = "equals"
	NotEquals   StringOperatorType = "notequals"
	Contains    StringOperatorType = "contains"
	NotContains StringOperatorType = "notcontains"
)

func ParseStringsOperator(s string) StringOperatorType {
	s = strings.ToLower(s)
	switch s {
	case "equals":
		return Equals
	case "notequals":
		return NotEquals
	case "contains":
		return Contains
	case "notcontains":
		return NotContains
	default:
		return Contains
	}
}

type StringFilterField struct {
	BaseFilter
	Operator    StringOperatorType
	CompareWith string
}

func (f StringFilterField) GetOperatorToString() string {
	return string(f.Operator)
}

func (f *StringFilterField) ToSQL() string {
	switch f.Operator {
	case Equals:
		return f.FieldName + " = '" + f.CompareWith + "'"
	case Contains:
		return f.FieldName + " LIKE '%" + f.CompareWith + "%'"
	case NotEquals:
		return f.FieldName + " <> '" + f.CompareWith + "'"
	case NotContains:
		return f.FieldName + " NOT LIKE '%" + f.CompareWith + "%'"
	default:
		return ""
	}
}

func (f StringFilterField) GetFieldName() string {
	return f.FieldName
}

func (f StringFilterField) GetValue() string {
	return f.CompareWith
}
