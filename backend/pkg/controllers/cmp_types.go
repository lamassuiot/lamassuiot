package controllers

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// PKIStatus represents the PKIStatus INTEGER from RFC 4210 §5.2.3.
//
//	PKIStatus ::= INTEGER {
//	    accepted                (0),
//	    grantedWithMods         (1),
//	    rejection               (2),
//	    waiting                 (3),
//	    revocationWarning       (4),
//	    revocationNotification  (5),
//	    keyUpdateWarning        (6)
//	}
type PKIStatus int

// PKIFreeText is a SEQUENCE of UTF8Strings (RFC 4210 §5.1.1).
//
//	PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
type PKIFreeText []asn1.RawValue

// PKIStatusInfo carries status information in CMP responses (RFC 4210 §5.2.3).
//
//	PKIStatusInfo ::= SEQUENCE {
//	    status        PKIStatus,
//	    statusString  PKIFreeText    OPTIONAL,
//	    failInfo      PKIFailureInfo OPTIONAL
//	}
type PKIStatusInfo struct {
	Raw          asn1.RawContent
	Status       PKIStatus
	StatusString PKIFreeText    `asn1:"optional,omitempty"`
	FailInfo     asn1.BitString `asn1:"optional,omitempty"`
}

// ErrorMsgContent is the body of an error PKIMessage (RFC 4210 §5.2.21).
//
//	ErrorMsgContent ::= SEQUENCE {
//	    pKIStatusInfo  PKIStatusInfo,
//	    errorCode      INTEGER           OPTIONAL,
//	    errorDetails   PKIFreeText       OPTIONAL
//	}
type ErrorMsgContent struct {
	PKIStatusInfo PKIStatusInfo
	ErrorCode     int         `asn1:"optional"`
	ErrorDetail   PKIFreeText `asn1:"optional"`
}

// nullDNGeneralName builds a GeneralName directoryName carrying an empty
// RDNSequence (NULL-DN).
//
//	GeneralName ::= CHOICE { directoryName [4] Name }
//	Name        ::= RDNSequence
//
// RFC 9483 §3.1 line 713 mandates NULL-DN as the response PKIHeader Sender
// when no protection certificate or shared secret is available to identify
// the responder, and line 803 mandates it as the Recipient when the intended
// recipient name is unknown.
func nullDNGeneralName() asn1.RawValue {
	name := struct {
		RDNSequence pkix.RDNSequence
	}{RDNSequence: pkix.RDNSequence{}}
	der, _ := asn1.MarshalWithParams(name, "tag:4,optional")
	return asn1.RawValue{FullBytes: der}
}

// defaultSenderGeneralName returns the NULL-DN GeneralName used as the
// response PKIHeader Sender when the DMS has no protection certificate
// configured (RFC 9483 §3.1 line 713).
func defaultSenderGeneralName() asn1.RawValue {
	return nullDNGeneralName()
}

// defaultRecipientGeneralName returns the NULL-DN GeneralName used as the
// response PKIHeader Recipient when the intended recipient cannot be derived
// from the incoming request (RFC 9483 §3.1 line 803).
func defaultRecipientGeneralName() asn1.RawValue {
	return nullDNGeneralName()
}
