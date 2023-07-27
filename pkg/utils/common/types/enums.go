package types

import (
	"strings"
)

type EnumOperatorType string

const (
	In    EnumOperatorType = "in"
	NotIn EnumOperatorType = "notin"
)

func ParseEnumOperator(s string) EnumOperatorType {
	s = strings.ToLower(s)
	switch s {
	case "in":
		return In
	case "notin":
		return NotIn
	default:
		return In
	}
}

type EnumFilterField struct {
	BaseFilter
	Operator   EnumOperatorType
	Collection []string
}

func (f *EnumFilterField) ToSQL() string {
	switch f.Operator {
	case In:
		return f.FieldName + " IN (" + strings.Join(f.Collection, ", ") + ") "
	case NotIn:
		return f.FieldName + " NOT IN (" + strings.Join(f.Collection, ", ") + ") "
	default:
		return ""
	}
}

func (f EnumFilterField) GetOperatorToString() string {
	return string(f.Operator)
}

func (f EnumFilterField) GetFieldName() string {
	return f.FieldName
}

func (f EnumFilterField) GetValue() string {
	return strings.Join(f.Collection, ",")
}
