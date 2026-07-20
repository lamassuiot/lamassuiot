package kga

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
)

// makeCert builds a self-signed certificate for key with the given EKUs and a
// SubjectKeyId, returning the parsed cert. Good enough for exercising the KGA
// envelope (the suite's trust-anchor/EKU checks are validated end-to-end, not here).
func makeCert(t *testing.T, key crypto.Signer, cn string, ekus []asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(len(cn)) + 1),
		Subject:      pkix.Name{CommonName: cn},
		SubjectKeyId: []byte(cn + "-ski"),
	}
	for _, e := range ekus {
		tmpl.UnknownExtKeyUsage = append(tmpl.UnknownExtKeyUsage, e)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

var oidKGACmKGA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 32}

// --- shared verification mirroring the RFC 9483 §4.1.6 suite validator -------

func decryptContent(t *testing.T, eci encryptedContentInfo, cek []byte) []byte {
	t.Helper()
	if !eci.ContentType.Equal(oidSignedData) {
		t.Fatalf("contentType = %v, want id-signedData", eci.ContentType)
	}
	if !eci.ContentEncryptionAlgorithm.Algorithm.Equal(oidAES256CBC) {
		t.Fatalf("content enc alg = %v, want aes256-cbc", eci.ContentEncryptionAlgorithm.Algorithm)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(eci.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil {
		t.Fatalf("decode IV: %v", err)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	pt := make([]byte, len(eci.EncryptedContent))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, eci.EncryptedContent)
	// strip PKCS#7 padding
	n := int(pt[len(pt)-1])
	return pt[:len(pt)-n]
}

// verifyKeyPackage parses the decrypted SignedData, checks the eContentType,
// signature over encapContentInfo, and returns the delivered private key.
func verifyKeyPackage(t *testing.T, signedDataDER []byte, kgaCert *x509.Certificate) crypto.Signer {
	t.Helper()
	var sd signedData
	if _, err := asn1.Unmarshal(signedDataDER, &sd); err != nil {
		t.Fatalf("decode SignedData: %v", err)
	}
	if sd.Version != 3 {
		t.Fatalf("SignedData.version = %d, want 3", sd.Version)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidCTKPAKeyPackage) {
		t.Fatalf("eContentType = %v, want id-ct-KP-aKeyPackage", sd.EncapContentInfo.EContentType)
	}
	if len(sd.SignerInfos) != 1 || sd.SignerInfos[0].Version != 3 {
		t.Fatalf("want exactly one SignerInfo v3, got %+v", sd.SignerInfos)
	}

	// Signature is over the DER of encapContentInfo (RFC 9483 §4.1.6 quirk).
	encapDER, err := asn1.Marshal(sd.EncapContentInfo)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(encapDER)
	switch pub := kgaCert.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sd.SignerInfos[0].Signature); err != nil {
			t.Fatalf("KGA RSA signature verify: %v", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, h[:], sd.SignerInfos[0].Signature) {
			t.Fatal("KGA ECDSA signature verify failed")
		}
	}

	// signedAttrs must carry contentType + messageDigest(hash of eContent).
	if len(sd.SignerInfos[0].SignedAttrs.FullBytes) == 0 {
		t.Fatal("signedAttrs missing")
	}

	// eContent = AsymmetricKeyPackage (SEQUENCE OF OneAsymmetricKey).
	var pkg asn1.RawValue
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &pkg); err != nil {
		t.Fatalf("decode AsymmetricKeyPackage: %v", err)
	}
	var oneKey asn1.RawValue
	if _, err := asn1.Unmarshal(pkg.Bytes, &oneKey); err != nil {
		t.Fatalf("decode OneAsymmetricKey: %v", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(oneKey.FullBytes)
	if err != nil {
		t.Fatalf("parse delivered PKCS#8 key: %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("delivered key %T is not a crypto.Signer", key)
	}
	return signer
}

func TestBuildKeyPackage_KTRI(t *testing.T) {
	kgaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kgaCert := makeCert(t, kgaKey, "kga", []asn1.ObjectIdentifier{oidKGACmKGA})

	recipKey, _ := rsa.GenerateKey(rand.Reader, 2048) // EE keyEncipherment key
	recipCert := makeCert(t, recipKey, "ee-ktri", nil)

	genKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // the delivered key

	der, err := BuildKeyPackage(BuildInput{
		GeneratedKey:  genKey,
		RecipientCert: recipCert,
		KGACert:       kgaCert,
		KGASigner:     kgaKey,
	})
	if err != nil {
		t.Fatalf("BuildKeyPackage: %v", err)
	}

	var env envelopedData
	if _, err := asn1.Unmarshal(der, &env); err != nil {
		t.Fatalf("decode EnvelopedData: %v", err)
	}
	// KTRI: recover the ktri (untagged SEQUENCE inside the recipientInfos SET).
	var ktri keyTransRecipientInfo
	if _, err := asn1.Unmarshal(env.RecipientInfos.Bytes, &ktri); err != nil {
		t.Fatalf("decode ktri: %v", err)
	}
	// The RFC 9483 §4.1.6 validator requires ktri version 2 with a
	// subjectKeyIdentifier rid ([0] IMPLICIT OCTET STRING = the recipient SKI).
	if ktri.Version != 2 {
		t.Fatalf("ktri version = %d, want 2", ktri.Version)
	}
	if ktri.RID.Class != asn1.ClassContextSpecific || ktri.RID.Tag != 0 {
		t.Fatalf("ktri rid tag = class %d/tag %d, want context/0 (subjectKeyIdentifier)", ktri.RID.Class, ktri.RID.Tag)
	}
	if !bytes.Equal(ktri.RID.Bytes, recipCert.SubjectKeyId) {
		t.Fatal("ktri rid subjectKeyIdentifier does not match recipient SKI")
	}
	if !ktri.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAESOAEP) {
		t.Fatalf("ktri keyEncAlg = %v, want id-RSAES-OAEP", ktri.KeyEncryptionAlgorithm.Algorithm)
	}
	var oaepParams rsaesOAEPParams
	if _, err := asn1.Unmarshal(ktri.KeyEncryptionAlgorithm.Parameters.FullBytes, &oaepParams); err != nil {
		t.Fatalf("decode RSAES-OAEP-params: %v", err)
	}
	if !oaepParams.HashFunc.Algorithm.Equal(oidSHA256) {
		t.Fatalf("OAEP hashFunc = %v, want SHA-256", oaepParams.HashFunc.Algorithm)
	}
	if !oaepParams.MaskGenFunc.Algorithm.Equal(oidMGF1) {
		t.Fatalf("OAEP maskGenFunc = %v, want id-mgf1", oaepParams.MaskGenFunc.Algorithm)
	}
	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, recipKey, ktri.EncryptedKey, nil)
	if err != nil {
		t.Fatalf("recover CEK: %v", err)
	}

	sd := decryptContent(t, env.EncryptedContentInfo, cek)
	delivered := verifyKeyPackage(t, sd, kgaCert)

	got := delivered.Public().(*ecdsa.PublicKey)
	if !got.Equal(&genKey.PublicKey) {
		t.Fatal("delivered key does not match the generated key")
	}

}

func TestBuildKeyPackage_KARI(t *testing.T) {
	kgaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kgaCert := makeCert(t, kgaKey, "kga", []asn1.ObjectIdentifier{oidKGACmKGA})

	origKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // RA originator (extraCerts[0])
	origCert := makeCert(t, origKey, "ra-originator", nil)

	recipKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // EE keyAgreement key
	recipCert := makeCert(t, recipKey, "ee-kari", nil)

	genKey, _ := rsa.GenerateKey(rand.Reader, 2048) // delivered key

	der, err := BuildKeyPackage(BuildInput{
		GeneratedKey:       genKey,
		RecipientCert:      recipCert,
		KARIOriginatorKey:  origKey,
		KARIOriginatorCert: origCert,
		KGACert:            kgaCert,
		KGASigner:          kgaKey,
	})
	if err != nil {
		t.Fatalf("BuildKeyPackage: %v", err)
	}

	var env envelopedData
	if _, err := asn1.Unmarshal(der, &env); err != nil {
		t.Fatalf("decode EnvelopedData: %v", err)
	}

	// Recover CEK exactly as the suite validator does: ECDH(ee_priv, originator_pub)
	// → X9.63 KDF → AES unwrap.
	eeECDH, _ := recipKey.ECDH()
	origECDHPub, _ := origKey.Public().(*ecdsa.PublicKey).ECDH()
	z, err := eeECDH.ECDH(origECDHPub)
	if err != nil {
		t.Fatalf("recipient ECDH: %v", err)
	}
	info, _ := eccCMSSharedInfo(oidAES256Wrap, 256)
	kek := ansiX963KDFSHA256(z, contentEncryptionKeyLen, info)

	// Parse the kari ([1] IMPLICIT) to get the wrapped CEK.
	var riRaw asn1.RawValue
	if _, err := asn1.Unmarshal(env.RecipientInfos.Bytes, &riRaw); err != nil {
		t.Fatalf("decode recipientInfo: %v", err)
	}
	kariSeq, err := reTag(riRaw.FullBytes, asn1.ClassUniversal, asn1.TagSequence)
	if err != nil {
		t.Fatalf("re-tag kari: %v", err)
	}
	var kari keyAgreeRecipientInfo
	if _, err := asn1.Unmarshal(kariSeq, &kari); err != nil {
		t.Fatalf("decode kari: %v", err)
	}
	if !kari.KeyEncryptionAlgorithm.Algorithm.Equal(oidDHSinglePassStdDHSHA256) {
		t.Fatalf("kari keyEncAlg = %v", kari.KeyEncryptionAlgorithm.Algorithm)
	}
	cek, err := aesKeyUnwrap(kek, kari.RecipientEncryptedKeys[0].EncryptedKey)
	if err != nil {
		t.Fatalf("unwrap CEK: %v", err)
	}

	sd := decryptContent(t, env.EncryptedContentInfo, cek)
	delivered := verifyKeyPackage(t, sd, kgaCert)

	got := delivered.Public().(*rsa.PublicKey)
	if !got.Equal(&genKey.PublicKey) {
		t.Fatal("delivered key does not match the generated key")
	}

	issuedCert := makeCert(t, genKey, "issued-kari", nil)
	bodyDER, err := corecmp.MarshalKGACertRepBody(0, int(corecmp.StatusAccepted), issuedCert.Raw, der)
	if err != nil {
		t.Fatal(err)
	}
	clientResult, err := corecmp.DecodeKGAResponse(corecmp.ParsedMessage{
		Body:       corecmp.EncodedBody{Type: corecmp.BodyIP, DER: bodyDER},
		ExtraCerts: []*x509.Certificate{origCert, kgaCert},
	}, corecmp.KGADecryptOptions{Recipient: recipKey})
	if err != nil {
		t.Fatal(err)
	}
	clientKey, ok := clientResult.PrivateKey.(*rsa.PrivateKey)
	if !ok || !clientKey.PublicKey.Equal(&genKey.PublicKey) {
		t.Fatal("CMP client did not recover the KARI-delivered key")
	}
}

// aesKeyUnwrap is the RFC 3394 inverse of aesKeyWrap, used only by the test to
// recover the CEK the way a recipient would.
func aesKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	a := make([]byte, 8)
	copy(a, wrapped[:8])
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], wrapped[(i+1)*8:(i+2)*8])
	}
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			copy(buf[:8], a)
			for k := 0; k < 8; k++ {
				buf[7-k] ^= byte(t >> (8 * k))
			}
			copy(buf[8:], r[i-1])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[i-1], buf[8:])
		}
	}
	out := make([]byte, 0, n*8)
	for i := 0; i < n; i++ {
		out = append(out, r[i]...)
	}
	return out, nil
}
