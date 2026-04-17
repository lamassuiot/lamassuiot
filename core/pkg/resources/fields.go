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
	"identity_slot":      JsonFilterFieldType,
}

var DeviceEventFilterableFields = map[string]FilterFieldType{
	"event_ts":          DateFilterFieldType,
	"event_type":        EnumFilterFieldType,
	"description":       StringFilterFieldType,
	"source":            StringFilterFieldType,
	"structured_fields": JsonFilterFieldType,
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

var AlertFilterableFields = map[string]FilterFieldType{
	"event_type": StringFilterFieldType,
	"seen_at":    DateFilterFieldType,
	"counter":    NumberFilterFieldType,
}
