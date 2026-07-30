package cmp

import "encoding/asn1"

// GeneralName is the ASN.1 GeneralName CHOICE used by CMP headers. Constructors
// such as GeneralNameDirectoryName ensure the CHOICE is tagged correctly.
type GeneralName = asn1.RawValue

// BodyType identifies a PKIBody CHOICE alternative.
type BodyType int

const (
	BodyIR       BodyType = BodyTagIR
	BodyIP       BodyType = BodyTagIP
	BodyCR       BodyType = BodyTagCR
	BodyCP       BodyType = BodyTagCP
	BodyP10CR    BodyType = BodyTagP10CR
	BodyPOPDecc  BodyType = BodyTagPopDecc
	BodyPOPDecr  BodyType = BodyTagPopDecr
	BodyKUR      BodyType = BodyTagKUR
	BodyKUP      BodyType = BodyTagKUP
	BodyRR       BodyType = BodyTagRR
	BodyRP       BodyType = BodyTagRP
	BodyCCR      BodyType = BodyTagCCR
	BodyCCP      BodyType = BodyTagCCP
	BodyPKIConf  BodyType = BodyTagPKIConf
	BodyNested   BodyType = BodyTagNested
	BodyGenMsg   BodyType = BodyTagGenMsg
	BodyGenRep   BodyType = BodyTagGenRep
	BodyError    BodyType = BodyTagError
	BodyCertConf BodyType = BodyTagCertConf
	BodyPollReq  BodyType = BodyTagPollReq
	BodyPollRep  BodyType = BodyTagPollRep
)

// FailureInfo identifies a PKIFailureInfo BIT STRING position.
type FailureInfo int

const (
	FailureBadAlg              FailureInfo = PKIFailureInfoBadAlg
	FailureBadMessageCheck     FailureInfo = PKIFailureInfoBadMessageCheck
	FailureBadRequest          FailureInfo = PKIFailureInfoBadRequest
	FailureBadTime             FailureInfo = PKIFailureInfoBadTime
	FailureBadCertID           FailureInfo = PKIFailureInfoBadCertID
	FailureBadDataFormat       FailureInfo = PKIFailureInfoBadDataFormat
	FailureWrongAuthority      FailureInfo = PKIFailureInfoWrongAuthority
	FailureIncorrectData       FailureInfo = PKIFailureInfoIncorrectData
	FailureMissingTimeStamp    FailureInfo = PKIFailureInfoMissingTimeStamp
	FailureBadPOP              FailureInfo = PKIFailureInfoBadPOP
	FailureCertRevoked         FailureInfo = PKIFailureInfoCertRevoked
	FailureCertConfirmed       FailureInfo = PKIFailureInfoCertConfirmed
	FailureWrongIntegrity      FailureInfo = PKIFailureInfoWrongIntegrity
	FailureBadRecipientNonce   FailureInfo = PKIFailureInfoBadRecipientNonce
	FailureTimeNotAvailable    FailureInfo = PKIFailureInfoTimeNotAvailable
	FailureUnacceptedPolicy    FailureInfo = PKIFailureInfoUnacceptedPolicy
	FailureUnacceptedExtension FailureInfo = PKIFailureInfoUnacceptedExtension
	FailureAddInfoNotAvailable FailureInfo = PKIFailureInfoAddInfoNotAvailable
	FailureBadSenderNonce      FailureInfo = PKIFailureInfoBadSenderNonce
	FailureBadCertTemplate     FailureInfo = PKIFailureInfoBadCertTemplate
	FailureSignerNotTrusted    FailureInfo = PKIFailureInfoSignerNotTrusted
	FailureTransactionIDInUse  FailureInfo = PKIFailureInfoTransactionIDInUse
	FailureUnsupportedVersion  FailureInfo = PKIFailureInfoUnsupportedVersion
	FailureNotAuthorized       FailureInfo = PKIFailureInfoNotAuthorized
	FailureSystemUnavail       FailureInfo = PKIFailureInfoSystemUnavail
	FailureSystemFailure       FailureInfo = PKIFailureInfoSystemFailure
	FailureDuplicateCertReq    FailureInfo = PKIFailureInfoDuplicateCertReq
)

const (
	StatusAccepted               PKIStatus = 0
	StatusGrantedWithMods        PKIStatus = 1
	StatusRejection              PKIStatus = 2
	StatusWaiting                PKIStatus = 3
	StatusRevocationWarning      PKIStatus = 4
	StatusRevocationNotification PKIStatus = 5
	StatusKeyUpdateWarning       PKIStatus = 6
)

// EncodedBody is a typed PKIBody payload. DER contains the encoded ASN.1 value
// placed inside the context-specific PKIBody alternative.
type EncodedBody struct {
	Type BodyType
	DER  []byte
}
