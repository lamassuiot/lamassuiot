package config

import "encoding/json"

// Password is redacted when rendered as text (config dumps, logs) but keeps its
// value in JSON, so it survives being stored and read back as part of a model.
type Password string

func (p Password) MarshalText() ([]byte, error) {
	return []byte("*************"), nil
}

func (p *Password) UnmarshalText(text []byte) error {
	*p = Password(text)
	return nil
}

func (p Password) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(p))
}
