package cms

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
)

// eccCMSSharedInfo builds the DER of ECC-CMS-SharedInfo (RFC 5753 §7.2):
// SEQUENCE { keyInfo AlgorithmIdentifier(keyWrapOID, no params),
// suppPubInfo [2] EXPLICIT OCTET STRING(keydatalen-in-bits, 4 bytes BE) }.
// entityUInfo is omitted (no UKM). Both the encoder (KARI build) and decoder
// (KARI decrypt) must derive the identical sharedInfo, so it lives here.
func eccCMSSharedInfo(keyWrapOID asn1.ObjectIdentifier, keyDataLenBits int) ([]byte, error) {
	keyInfo, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: keyWrapOID})
	if err != nil {
		return nil, err
	}
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(keyDataLenBits))
	octet, err := asn1.Marshal(lenBytes) // OCTET STRING
	if err != nil {
		return nil, err
	}
	suppPubInfo, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: octet,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(append([]byte{}, keyInfo...), suppPubInfo...),
	})
}

// ansiX963KDFSHA256 is the ANSI-X9.63 KDF (SHA-256): K = H(Z || counter || info)
// concatenated until keyLen bytes (RFC 5753). counter is a 4-byte big-endian
// value starting at 1.
func ansiX963KDFSHA256(z []byte, keyLen int, info []byte) []byte {
	var out []byte
	counter := uint32(1)
	for len(out) < keyLen {
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], counter)
		h := sha256.New()
		h.Write(z)
		h.Write(ctr[:])
		h.Write(info)
		out = append(out, h.Sum(nil)...)
		counter++
	}
	return out[:keyLen]
}
