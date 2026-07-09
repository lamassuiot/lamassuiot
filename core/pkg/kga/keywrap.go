package kga

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
)

// rfc3394IV is the default initial value for AES Key Wrap (RFC 3394 §2.2.3.1).
var rfc3394IV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aesKeyWrap wraps plaintext (the CEK) with kek using the RFC 3394 AES Key Wrap
// algorithm. plaintext length must be a multiple of 8 and at least 16 bytes.
func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 || len(plaintext) < 16 {
		return nil, fmt.Errorf("key-wrap plaintext must be a multiple of 8 bytes and at least 16 (got %d)", len(plaintext))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(plaintext) / 8
	a := make([]byte, 8)
	copy(a, rfc3394IV)
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:(i+1)*8])
	}

	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i-1])
			block.Encrypt(buf, buf)

			copy(a, buf[:8])
			t := uint64(n*j + i)
			var tb [8]byte
			binary.BigEndian.PutUint64(tb[:], t)
			for k := 0; k < 8; k++ {
				a[k] ^= tb[k]
			}
			copy(r[i-1], buf[8:])
		}
	}

	out := make([]byte, 0, 8*(n+1))
	out = append(out, a...)
	for i := 0; i < n; i++ {
		out = append(out, r[i]...)
	}
	return out, nil
}
