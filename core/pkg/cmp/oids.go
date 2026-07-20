package cmp

import "encoding/asn1"

// OIDRSAEncryption returns id-rsaEncryption.
func OIDRSAEncryption() asn1.ObjectIdentifier { return cloneOID(oidRSAEncryption) }

// OIDECPublicKey returns id-ecPublicKey.
func OIDECPublicKey() asn1.ObjectIdentifier { return cloneOID(oidECPublicKey) }

// OIDImplicitConfirm returns id-it-implicitConfirm.
func OIDImplicitConfirm() asn1.ObjectIdentifier { return cloneOID(oidImplicitConfirm) }

// OIDOrigPKIMessage returns id-it-origPKIMessage.
func OIDOrigPKIMessage() asn1.ObjectIdentifier { return cloneOID(oidOrigPKIMessage) }

// OIDPasswordBasedMAC returns id-PasswordBasedMac.
func OIDPasswordBasedMAC() asn1.ObjectIdentifier { return cloneOID(oidPasswordBasedMAC) }

// OIDDHBasedMAC returns id-DHBasedMac.
func OIDDHBasedMAC() asn1.ObjectIdentifier { return cloneOID(oidDHBasedMAC) }

// OIDExtensionRequest returns the PKCS#9 extensionRequest attribute OID.
func OIDExtensionRequest() asn1.ObjectIdentifier { return cloneOID(oidExtensionRequest) }

// OIDSubjectAltNameExt returns the X.509 subjectAltName extension OID.
func OIDSubjectAltNameExt() asn1.ObjectIdentifier { return cloneOID(oidSubjectAltNameExt) }

// OIDRegCtrlOldCertID returns id-regCtrl-oldCertID.
func OIDRegCtrlOldCertID() asn1.ObjectIdentifier { return cloneOID(oidRegCtrlOldCertID) }

// OIDRegCtrlRegToken returns id-regCtrl-regToken.
func OIDRegCtrlRegToken() asn1.ObjectIdentifier { return cloneOID(oidRegCtrlRegToken) }

// OIDRegCtrlAuthenticator returns id-regCtrl-authenticator.
func OIDRegCtrlAuthenticator() asn1.ObjectIdentifier { return cloneOID(oidRegCtrlAuthenticator) }

func cloneOID(oid asn1.ObjectIdentifier) asn1.ObjectIdentifier {
	return append(asn1.ObjectIdentifier(nil), oid...)
}
