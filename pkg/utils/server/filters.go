package server

type FilterType int64

const (
	StringFilterType FilterType = iota
	DateFilterType
	NumberFilterType
	EnumFilterType
)

type FilterField struct {
	FieldName string
	FieldType FilterType
}
