package config

type Password string

func (p Password) MarshalText() ([]byte, error) {
	return []byte("*************"), nil
}

func (p *Password) UnmarshalText(text []byte) (err error) {
	pw := string(text)
	p = (*Password)(&pw)
	return nil
}
