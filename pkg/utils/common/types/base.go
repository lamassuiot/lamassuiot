package types

type baseFilter struct {
	FieldName string
}

type Filter interface {
	ToSQL() string

	GetOperatorToString() string
	GetFieldName() string
	GetValue() string
}
