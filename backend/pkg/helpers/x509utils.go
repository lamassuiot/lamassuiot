package helpers

import (
	"fmt"
	"strings"
)

func FormatHexWithColons(data []byte) string {
	hexParts := make([]string, len(data))
	for i, b := range data {
		hexParts[i] = fmt.Sprintf("%02X", b) // Format each byte as uppercase hex
	}
	return strings.Join(hexParts, ":") // Join with colons
}
