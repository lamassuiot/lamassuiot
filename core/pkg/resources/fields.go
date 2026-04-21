package resources

var CertificateFilterableFields = map[string]FilterFieldType{
	"type":                          EnumFilterFieldType,
	"serial_number":                 StringFilterFieldType,
	"subject.common_name":           StringFilterFieldType,
	"subject_key_id":                StringFilterFieldType,
	"issuer_meta.id":                StringFilterFieldType,
	"status":                        EnumFilterFieldType,
	"engine_id":                     StringFilterFieldType,
	"valid_to":                      DateFilterFieldType,
	"valid_from":                    DateFilterFieldType,
	"revocation_timestamp":          DateFilterFieldType,
	"revocation_reason":             EnumFilterFieldType,
	"metadata":                      JsonFilterFieldType,
	"extensions.key_usage":          StringArrayFilterFieldType,
	"extensions.extended_key_usage": StringArrayFilterFieldType,
	"is_ca":                         EnumFilterFieldType,
}

var CAFilterableFields = map[string]FilterFieldType{
	"id":                            StringFilterFieldType,
	"profile_id":                    StringFilterFieldType,
	"type":                          EnumFilterFieldType,
	"serial_number":                 StringFilterFieldType,
	"subject.common_name":           StringFilterFieldType,
	"subject_key_id":                StringFilterFieldType,
	"issuer_meta.id":                StringFilterFieldType,
	"status":                        EnumFilterFieldType,
	"engine_id":                     StringFilterFieldType,
	"valid_to":                      DateFilterFieldType,
	"valid_from":                    DateFilterFieldType,
	"revocation_timestamp":          DateFilterFieldType,
	"revocation_reason":             EnumFilterFieldType,
	"metadata":                      JsonFilterFieldType,
	"extensions.key_usage":          StringArrayFilterFieldType,
	"extensions.extended_key_usage": StringArrayFilterFieldType,
	"is_ca":                         EnumFilterFieldType,
}

var KMSFilterableFields = map[string]FilterFieldType{
	"key_id":          StringFilterFieldType,
	"engine_id":       StringFilterFieldType,
	"has_private_key": EnumFilterFieldType,
	"algorithm":       StringFilterFieldType,
	"size":            NumberFilterFieldType,
	"public_key":      StringFilterFieldType,
	"status":          StringFilterFieldType,
	"creation_ts":     DateFilterFieldType,
	"name":            StringFilterFieldType,
	"tags":            StringArrayFilterFieldType,
	"metadata":        JsonFilterFieldType,
}

var IssuanceProfileFilterableFields = map[string]FilterFieldType{
	"id":   StringFilterFieldType,
	"name": StringFilterFieldType,
}

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
