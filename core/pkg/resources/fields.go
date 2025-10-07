package resources

var DMSFiltrableFields = map[string]FilterFieldType{
	"id":          StringFilterFieldType,
	"name":        StringFilterFieldType,
	"creation_ts": DateFilterFieldType,
}

var DeviceFiltrableFields = map[string]FilterFieldType{
	"id":                 StringFilterFieldType,
	"dms_owner":          StringFilterFieldType,
	"creation_timestamp": DateFilterFieldType,
	"status":             EnumFilterFieldType,
	"tags":               StringArrayFilterFieldType,
}

var CertificateFiltrableFields = map[string]FilterFieldType{
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
}
