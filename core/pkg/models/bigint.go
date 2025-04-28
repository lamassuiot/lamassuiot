package models

import (
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
