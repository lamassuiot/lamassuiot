package helpers

import (
	"encoding/hex"
	"math/big"
)

// SerialNumberToHexString converts a big.Int serial number to its hexadecimal string representation.
// It ensures that the output is in lowercase and has an even length by padding with a leading zero if necessary.
func SerialNumberToHexString(n *big.Int) string {
	n = new(big.Int).Abs(n)
	if n.Sign() == 0 {
		return "00"
	}
	return hex.EncodeToString(n.Bytes())
}
