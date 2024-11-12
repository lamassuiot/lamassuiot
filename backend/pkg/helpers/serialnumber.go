package helpers

import (
	"bytes"
	"fmt"
	"math/big"
)

func insertNth(s string, n int, sep rune) string {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	var buffer bytes.Buffer
	var n1 = n - 1
	var l1 = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%n == n1 && i != l1 {
			buffer.WriteRune(sep)
		}
	}
	return buffer.String()
}

func toHexInt(n *big.Int) string {
	return fmt.Sprintf("%x", n) // or %X or upper case
}

func SerialNumberToString(n *big.Int) string {
	return insertNth(toHexInt(new(big.Int).Abs(n)), 2, '-')
}
