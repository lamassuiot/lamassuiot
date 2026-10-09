package dto

import (
	"encoding/json"
	"fmt"
)

// FlexEntityKey accepts either a JSON string or a JSON object for the entity key
// in request payloads:
//
//	"entityKey": "device-42"                   // plain string – only valid for single-column PK schemas
//	"entityKey": {"device_id": "device-42"}    // object – works for single and composite PKs
//
// When a plain string is provided the service resolves the PK column name from the
// schema definition automatically.  Composite-PK schemas always require the object form.
type FlexEntityKey struct {
	m      map[string]string
	s      string
	strSet bool
}

// IsEmpty reports whether no entity key was provided.
func (f FlexEntityKey) IsEmpty() bool {
	return !f.strSet && len(f.m) == 0
}

// IsString reports whether the value was provided as a plain string.
func (f FlexEntityKey) IsString() bool { return f.strSet }

// Map returns the map representation (nil when provided as a plain string).
func (f FlexEntityKey) Map() map[string]string { return f.m }

// Str returns the raw string value (empty when provided as an object).
func (f FlexEntityKey) Str() string { return f.s }

// NewFlexEntityKeyFromMap wraps an existing map[string]string as a FlexEntityKey.
// Useful in SDK and test code where the key is already resolved.
func NewFlexEntityKeyFromMap(m map[string]string) FlexEntityKey {
	return FlexEntityKey{m: m}
}

// MarshalJSON implements json.Marshaler.
// A map-backed key serializes as a JSON object; a string-backed key serializes as a JSON string;
// an empty key serializes as null.
func (f FlexEntityKey) MarshalJSON() ([]byte, error) {
	if f.strSet {
		return json.Marshal(f.s)
	}
	if len(f.m) > 0 {
		return json.Marshal(f.m)
	}
	return []byte("null"), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (f *FlexEntityKey) UnmarshalJSON(data []byte) error {
	var m map[string]string
	if err := json.Unmarshal(data, &m); err == nil {
		f.m = m
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		f.s = s
		f.strSet = true
		return nil
	}
	return fmt.Errorf(`entityKey must be a string ("id-value") or an object ({"col": "value"})`)
}
