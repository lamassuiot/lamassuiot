package resources

var DMSFilterableFields = map[string]FilterFieldType{
	"id":            StringFilterFieldType,
	"name":          StringFilterFieldType,
	"creation_date": DateFilterFieldType,
	"metadata":      JsonFilterFieldType,
	"settings":      JsonFilterFieldType,
}

var DeviceFilterableFields = map[string]FilterFieldType{
	"id":                 StringFilterFieldType,
	"dms_owner":          StringFilterFieldType,
	"creation_timestamp": DateFilterFieldType,
	"status":             EnumFilterFieldType,
	"tags":               StringArrayFilterFieldType,
	"metadata":           JsonFilterFieldType,
}

var CertificateFilterableFields = map[string]FilterFieldType{
	"type":                 EnumFilterFieldType,
	"serial_number":        StringFilterFieldType,
	"subject.common_name":  StringFilterFieldType,
	"subject_key_id":       StringFilterFieldType,
	"issuer_meta.id":       StringFilterFieldType,
	"status":               EnumFilterFieldType,
	"engine_id":            StringFilterFieldType,
	"valid_to":             DateFilterFieldType,
	"valid_from":           DateFilterFieldType,
	"revocation_timestamp": DateFilterFieldType,
	"revocation_reason":    EnumFilterFieldType,
	"metadata":             JsonFilterFieldType,
}
