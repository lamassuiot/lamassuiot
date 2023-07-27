package types

import (
	"strconv"
	"strings"
)

type NumberOperatorType string

const (
	LessThan       NumberOperatorType = "lessthan"
	GreaterThan    NumberOperatorType = "greaterthan"
	LessOrEqual    NumberOperatorType = "lessorequal"
	GreaterOrEqual NumberOperatorType = "greaterorequal"
	Equal          NumberOperatorType = "equal"
	NotEqual       NumberOperatorType = "notequal"
)

func ParseNumberOperator(s string) NumberOperatorType {
	s = strings.ToLower(s)
	switch s {
	case "lessthan":
		return LessThan
	case "greaterthan":
		return GreaterThan
	case "lessorequal":
		return LessOrEqual
	case "greaterorequal":
		return GreaterOrEqual
	case "equal":
		return Equal
	case "notequal":
		return NotEqual
	default:
		return Equal
	}
}

type NumberFilterField struct {
	BaseFilter
	Operator    NumberOperatorType
	CompareWith int
}

func (f *NumberFilterField) ToSQL() string {
	comparwWithStringValue := strconv.Itoa(f.CompareWith)
	switch f.Operator {
	case LessThan:
		return f.FieldName + "< '" + comparwWithStringValue + "' "
	case GreaterThan:
		return f.FieldName + "> '" + comparwWithStringValue + "' "
	case LessOrEqual:
		return f.FieldName + "<= '" + comparwWithStringValue + "' "
	case GreaterOrEqual:
		return f.FieldName + ">= '" + comparwWithStringValue + "' "
	case Equal:
		return f.FieldName + "= '" + comparwWithStringValue + "' "
	case NotEqual:
		return f.FieldName + "<> '" + comparwWithStringValue + "' "
	default:
		return ""
	}
}

func (f NumberFilterField) GetOperatorToString() string {
	return string(f.Operator)
}

func (f NumberFilterField) GetFieldName() string {
	return f.FieldName
}

func (f NumberFilterField) GetValue() string {
	return strconv.Itoa(f.CompareWith)
}
