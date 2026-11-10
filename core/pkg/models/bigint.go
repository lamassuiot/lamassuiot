package models

import (
	"encoding/json"
	"fmt"
	"math/big"
)

type BigInt struct {
	*big.Int
}

func (c BigInt) MarshalText() ([]byte, error) {
	text := []byte(c.String())
	return text, nil
}

func (c *BigInt) UnmarshalText(text []byte) error {
	c.Int = new(big.Int)
	c.Int.SetString(string(text), 10)

	return nil
}

// UnmarshalJSON allocates the embedded integer before decoding an API response.
// Numeric JSON and decimal strings are both accepted without converting through float64.
func (c *BigInt) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
		value, ok := new(big.Int).SetString(text, 10)
		if !ok {
			return fmt.Errorf("invalid integer %q", text)
		}
		c.Int = value
		return nil
	}
	value := new(big.Int)
	if err := value.UnmarshalJSON(data); err != nil {
		return err
	}
	c.Int = value
	return nil
}
