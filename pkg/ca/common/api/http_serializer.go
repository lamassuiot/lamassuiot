package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"

	"github.com/lib/pq"
)

type SupportedKeyTypeInfoSerialized struct {
	Type        string `json:"type"`
	MinimumSize int    `json:"minimum_size"`
	MaximumSize int    `json:"maximum_size"`
}

func (s *SupportedKeyTypeInfo) Serialize() *SupportedKeyTypeInfoSerialized {
	return &SupportedKeyTypeInfoSerialized{
		Type:        string(s.Type),
		MinimumSize: s.MinimumSize,
		MaximumSize: s.MaximumSize,
	}
}

func (s *SupportedKeyTypeInfoSerialized) Deserialize() *SupportedKeyTypeInfo {
	return &SupportedKeyTypeInfo{
		Type:        ParseKeyType(s.Type),
		MinimumSize: s.MinimumSize,
		MaximumSize: s.MaximumSize,
	}
}

type EngineProviderInfoSerialized struct {
	Provider          string                           `json:"provider"`
	CryptokiVersion   string                           `json:"cryptoki_version"`
	Manufacturer      string                           `json:"manufacturer"`
	Model             string                           `json:"model"`
	Library           string                           `json:"library"`
	SupportedKeyTypes []SupportedKeyTypeInfoSerialized `json:"supported_key_types"`
}

func (e *EngineProviderInfo) Serialize() EngineProviderInfoSerialized {
	keys := make([]SupportedKeyTypeInfoSerialized, 0)
	for _, key := range e.SupportedKeyTypes {
		keys = append(keys, *key.Serialize())
	}

	serializer := EngineProviderInfoSerialized{
		Provider:          e.Provider,
		CryptokiVersion:   e.CryptokiVersion,
		Manufacturer:      e.Manufacturer,
		Model:             e.Model,
		Library:           e.Library,
		SupportedKeyTypes: keys,
	}
	return serializer
}

func (e *EngineProviderInfoSerialized) Deserialize() *EngineProviderInfo {
	keys := make([]SupportedKeyTypeInfo, 0)
	for _, key := range e.SupportedKeyTypes {
		keys = append(keys, *key.Deserialize())
	}

	return &EngineProviderInfo{
		Provider:          e.Provider,
		CryptokiVersion:   e.CryptokiVersion,
		Manufacturer:      e.Manufacturer,
		Model:             e.Model,
		Library:           e.Library,
		SupportedKeyTypes: keys,
	}
}

type SubjectSerialized struct {
	CommonName       string `json:"common_name"`
	Organization     string `json:"organization"`
	OrganizationUnit string `json:"organization_unit"`
	Country          string `json:"country"`
	State            string `json:"state"`
	Locality         string `json:"locality"`
}

func (o *Subject) Serialize() SubjectSerialized {
	serializer := SubjectSerialized{
		CommonName:       o.CommonName,
		Organization:     o.Organization,
		OrganizationUnit: o.OrganizationUnit,
		Country:          o.Country,
		State:            o.State,
		Locality:         o.Locality,
	}
	return serializer
}

func (o *SubjectSerialized) Deserialize() Subject {
	serializer := Subject{
		CommonName:       o.CommonName,
		Organization:     o.Organization,
		OrganizationUnit: o.OrganizationUnit,
		Country:          o.Country,
		State:            o.State,
		Locality:         o.Locality,
	}
	return serializer
}

type KeyStrengthMetadataSerialized struct {
	KeyType     string `json:"type"`
	KeyBits     int    `json:"bits"`
	KeyStrength string `json:"strength"`
}

func (o *KeyStrengthMetadata) Serialize() KeyStrengthMetadataSerialized {
	serializer := KeyStrengthMetadataSerialized{
		KeyType:     string(o.KeyType),
		KeyBits:     o.KeyBits,
		KeyStrength: string(o.KeyStrength),
	}
	return serializer
}

func (o *KeyStrengthMetadataSerialized) Deserialize() KeyStrengthMetadata {
	serializer := KeyStrengthMetadata{
		KeyType:     ParseKeyType(o.KeyType),
		KeyBits:     o.KeyBits,
		KeyStrength: ParseKeyStrength(o.KeyStrength),
	}
	return serializer
}

type CertificateSerialized struct {
	CAName              string                        `json:"name"`
	Status              string                        `json:"status"`
	Certificate         string                        `json:"certificate"`
	SerialNumber        string                        `json:"serial_number"`
	KeyMetadata         KeyStrengthMetadataSerialized `json:"key_metadata"`
	Subject             SubjectSerialized             `json:"subject"`
	ValidFrom           int                           `json:"valid_from"`
	ValidTo             int                           `json:"valid_to"`
	RevocationTimestamp int                           `json:"revocation_timestamp,omitempty"`
	RevocationReason    string                        `json:"revocation_reason,omitempty"`
}

func (o *Certificate) Serialize() CertificateSerialized {
	var certificateString string = ""
	if o.Certificate != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: o.Certificate.Raw})
		certEnc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(certEnc, pemCert)
		certificateString = string(certEnc)
	}

	serializer := CertificateSerialized{
		CAName:           o.CAName,
		Status:           string(o.Status),
		SerialNumber:     o.SerialNumber,
		ValidFrom:        int(o.ValidFrom.UnixMilli()),
		ValidTo:          int(o.ValidTo.UnixMilli()),
		RevocationReason: o.RevocationReason,
		KeyMetadata:      o.KeyMetadata.Serialize(),
		Subject:          o.Subject.Serialize(),
		Certificate:      certificateString,
	}

	if o.RevocationTimestamp.Valid {
		serializer.RevocationTimestamp = int(o.RevocationTimestamp.Time.UnixMilli())
	}

	return serializer
}

func (o *CertificateSerialized) Deserialize() Certificate {
	var certificate *x509.Certificate = nil

	decodedCert, err := base64.StdEncoding.DecodeString(o.Certificate)
	if err == nil {
		certBlock, _ := pem.Decode([]byte(decodedCert))
		if certBlock != nil {
			certificate, _ = x509.ParseCertificate(certBlock.Bytes)
		}
	}

	serializer := Certificate{
		CAName:           o.CAName,
		Status:           ParseCertificateStatus(o.Status),
		SerialNumber:     o.SerialNumber,
		ValidFrom:        time.UnixMilli(int64(o.ValidFrom)),
		ValidTo:          time.UnixMilli(int64(o.ValidTo)),
		RevocationReason: o.RevocationReason,
		KeyMetadata:      o.KeyMetadata.Deserialize(),
		Subject:          o.Subject.Deserialize(),
		Certificate:      certificate,
	}

	if o.RevocationTimestamp > 0 {
		serializer.RevocationTimestamp = pq.NullTime{
			Time:  time.UnixMilli(int64(o.RevocationTimestamp)),
			Valid: true,
		}
		serializer.RevocationReason = o.RevocationReason
	} else {
		serializer.RevocationTimestamp = pq.NullTime{
			Valid: false,
		}
	}

	return serializer
}

type CACertificateSerialized struct {
	CertificateSerialized
	WithPrivateKey   bool           `json:"with_private_key"`
	IssuanceDate     *time.Time     `json:"issuance_date,omitempty"`
	IssuanceDuration *time.Duration `json:"issuance_duration,omitempty"`
	IssuanceType     string         `json:"issuance_type,omitempty"`
}

func (o *CACertificate) Serialize() CACertificateSerialized {
	if o.IssuanceDate == nil {
		serializer := CACertificateSerialized{
			CertificateSerialized: o.Certificate.Serialize(),
			IssuanceDuration:      o.IssuanceDuration,
			IssuanceType:          o.IssuanceType,
			WithPrivateKey:        o.WithPrivateKey,
		}
		return serializer
	} else {
		serializer := CACertificateSerialized{
			CertificateSerialized: o.Certificate.Serialize(),
			IssuanceDate:          o.IssuanceDate,
			IssuanceType:          o.IssuanceType,
			WithPrivateKey:        o.WithPrivateKey,
		}
		return serializer
	}

}

func (o *CACertificateSerialized) Deserialize() CACertificate {
	serializer := CACertificate{
		Certificate:      o.CertificateSerialized.Deserialize(),
		IssuanceDuration: o.IssuanceDuration,
		IssuanceType:     o.IssuanceType,
		WithPrivateKey:   o.WithPrivateKey,
		IssuanceDate:     o.IssuanceDate,
	}
	return serializer
}

// -------------------------------------------------------------
type GetStatsOutputSerialized struct {
	IssuedCerts int       `json:"issued_certificates"`
	CAs         int       `json:"cas"`
	ScanDate    time.Time `json:"scan_date"`
}

func (o *GetStatsOutput) Serialize() GetStatsOutputSerialized {
	serializer := GetStatsOutputSerialized{
		IssuedCerts: o.IssuedCerts,
		CAs:         o.CAs,
		ScanDate:    o.ScanDate,
	}
	return serializer
}

func (o *GetStatsOutputSerialized) Deserialize() GetStatsOutput {
	serializer := GetStatsOutput{
		IssuedCerts: o.IssuedCerts,
		CAs:         o.CAs,
		ScanDate:    o.ScanDate,
	}
	return serializer
}

// -------------------------------------------------------------

type CreateCAOutputSerialized struct {
	CACertificateSerialized
}

func (o *CreateCAOutput) Serialize() CreateCAOutputSerialized {
	serializer := CreateCAOutputSerialized{
		CACertificateSerialized: o.CACertificate.Serialize(),
	}
	return serializer
}

func (o *CreateCAOutputSerialized) Deserialize() CreateCAOutput {
	serializer := CreateCAOutput{
		CACertificate: o.CACertificateSerialized.Deserialize(),
	}
	return serializer
}

// -------------------------------------------------------------

type ImportCAOutputSerialized struct {
	CACertificateSerialized
}

func (o *ImportCAOutput) Serialize() ImportCAOutputSerialized {
	serializer := ImportCAOutputSerialized{
		CACertificateSerialized: o.CACertificate.Serialize(),
	}
	return serializer
}

func (o *ImportCAOutputSerialized) Deserialize() ImportCAOutput {
	serializer := ImportCAOutput{
		CACertificate: o.CACertificateSerialized.Deserialize(),
	}
	return serializer
}

// -------------------------------------------------------------

type GetCAsOutputSerialized struct {
	TotalCAs int                       `json:"total_cas"`
	CAs      []CACertificateSerialized `json:"cas"`
}

func (o *GetCAsOutput) Serialize() GetCAsOutputSerialized {
	serializedCAs := make([]CACertificateSerialized, 0)
	for _, ca := range o.CAs {
		serializedCAs = append(serializedCAs, ca.Serialize())
	}
	serializer := GetCAsOutputSerialized{
		TotalCAs: o.TotalCAs,
		CAs:      serializedCAs,
	}
	return serializer
}

func (o *GetCAsOutputSerialized) Deserialize() GetCAsOutput {
	serializedCAs := make([]CACertificate, 0)
	for _, ca := range o.CAs {
		serializedCAs = append(serializedCAs, ca.Deserialize())
	}
	serializer := GetCAsOutput{
		TotalCAs: o.TotalCAs,
		CAs:      serializedCAs,
	}
	return serializer
}

// -------------------------------------------------------------
type GetCAByNameOutputSerialized struct {
	CACertificateSerialized
}

func (o *GetCAByNameOutput) Serialize() GetCAByNameOutputSerialized {
	return GetCAByNameOutputSerialized{
		CACertificateSerialized: o.CACertificate.Serialize(),
	}
}

func (o *GetCAByNameOutputSerialized) Deserialize() GetCAByNameOutput {
	return GetCAByNameOutput{
		CACertificate: o.CACertificateSerialized.Deserialize(),
	}
}

type SignOutputSerialized struct {
	Signature        string         `json:"signature"`
	SigningAlgorithm SigningAlgType `json:"signing_algorithm"`
}

func (o *SignOutput) Serialize() SignOutputSerialized {
	return SignOutputSerialized{
		Signature:        o.Signature,
		SigningAlgorithm: o.SigningAlgorithm,
	}
}

func (o *SignOutputSerialized) Deserialize() SignOutput {
	return SignOutput{
		Signature:        o.Signature,
		SigningAlgorithm: o.SigningAlgorithm,
	}
}

type VerifyOutputSerialized struct {
	VerificationResult bool `json:"verification"`
}

func (o *VerifyOutput) Serialize() VerifyOutputSerialized {
	return VerifyOutputSerialized{
		VerificationResult: o.VerificationResult,
	}
}

func (o *VerifyOutputSerialized) Deserialize() VerifyOutput {
	return VerifyOutput{
		VerificationResult: o.VerificationResult,
	}
}

// -------------------------------------------------------------
type RevokeCAOutputSerialized struct {
	CACertificateSerialized
}

func (o *RevokeCAOutput) Serialize() RevokeCAOutputSerialized {
	return RevokeCAOutputSerialized{
		CACertificateSerialized: o.CACertificate.Serialize(),
	}
}

func (o *RevokeCAOutputSerialized) Deserialize() RevokeCAOutput {
	return RevokeCAOutput{
		CACertificate: o.CACertificateSerialized.Deserialize(),
	}
}

// -------------------------------------------------------------
type SignCertificateRequestOutputSerialized struct {
	Certificate   string `json:"certificate"`
	CACertificate string `json:"ca_certificate"`
}

func (o *SignCertificateRequestOutput) Serialize() SignCertificateRequestOutputSerialized {
	var certificateString string = ""
	if o.Certificate != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: o.Certificate.Raw})
		certEnc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(certEnc, pemCert)
		certificateString = string(certEnc)
	}

	var CACertificateString string = ""
	if o.CACertificate != nil {
		pemCACert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: o.CACertificate.Raw})
		CACertEnc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCACert)))
		base64.StdEncoding.Encode(CACertEnc, pemCACert)
		CACertificateString = string(CACertEnc)
	}

	return SignCertificateRequestOutputSerialized{
		Certificate:   certificateString,
		CACertificate: CACertificateString,
	}
}

func (o *SignCertificateRequestOutputSerialized) Deserialize() SignCertificateRequestOutput {
	var certificate *x509.Certificate = nil
	decodedCert, err := base64.StdEncoding.DecodeString(o.Certificate)
	if err == nil {
		certBlock, _ := pem.Decode([]byte(decodedCert))
		if certBlock != nil {
			certificate, _ = x509.ParseCertificate(certBlock.Bytes)
		}
	}

	var CACertificate *x509.Certificate = nil
	decodedCACert, err := base64.StdEncoding.DecodeString(o.CACertificate)
	if err == nil {
		CACertBlock, _ := pem.Decode([]byte(decodedCACert))
		if CACertBlock != nil {
			CACertificate, _ = x509.ParseCertificate(CACertBlock.Bytes)
		}
	}

	return SignCertificateRequestOutput{
		Certificate:   certificate,
		CACertificate: CACertificate,
	}
}

// -------------------------------------------------------------
type RevokeCertificateOutputSerialized struct {
	CertificateSerialized
}

func (o *RevokeCertificateOutput) Serialize() RevokeCertificateOutputSerialized {
	return RevokeCertificateOutputSerialized{
		CertificateSerialized: o.Certificate.Serialize(),
	}
}

func (o *RevokeCertificateOutputSerialized) Deserialize() RevokeCertificateOutput {
	return RevokeCertificateOutput{
		Certificate: o.CertificateSerialized.Deserialize(),
	}
}

// -------------------------------------------------------------

type UpdateCertificateStatusOutputSerialized struct {
	CertificateSerialized
}

func (o *UpdateCertificateStatusOutput) Serialize() UpdateCertificateStatusOutputSerialized {
	return UpdateCertificateStatusOutputSerialized{
		CertificateSerialized: o.Certificate.Serialize(),
	}
}

func (o *UpdateCertificateStatusOutputSerialized) Deserialize() UpdateCertificateStatusOutput {
	return UpdateCertificateStatusOutput{
		Certificate: o.CertificateSerialized.Deserialize(),
	}
}

// -------------------------------------------------------------
type GetCertificateBySerialNumberOutputSerialized struct {
	CertificateSerialized
}

func (o *GetCertificateBySerialNumberOutput) Serialize() GetCertificateBySerialNumberOutputSerialized {
	return GetCertificateBySerialNumberOutputSerialized{
		CertificateSerialized: o.Certificate.Serialize(),
	}
}

func (o *GetCertificateBySerialNumberOutputSerialized) Deserialize() GetCertificateBySerialNumberOutput {
	return GetCertificateBySerialNumberOutput{
		Certificate: o.CertificateSerialized.Deserialize(),
	}
}

// -------------------------------------------------------------
type GetCertificatesOutputSerialized struct {
	TotalCertificates int                     `json:"total_certificates"`
	Certificates      []CertificateSerialized `json:"certificates"`
}

func (o *GetCertificatesOutput) Serialize() GetCertificatesOutputSerialized {
	serializedCertificates := make([]CertificateSerialized, 0)
	for _, ca := range o.Certificates {
		serializedCertificates = append(serializedCertificates, ca.Serialize())
	}
	serializer := GetCertificatesOutputSerialized{
		TotalCertificates: o.TotalCertificates,
		Certificates:      serializedCertificates,
	}
	return serializer
}

func (o *GetCertificatesOutputSerialized) Deserialize() GetCertificatesOutput {
	serializedCertificates := make([]Certificate, 0)
	for _, ca := range o.Certificates {
		serializedCertificates = append(serializedCertificates, ca.Deserialize())
	}
	serializer := GetCertificatesOutput{
		TotalCertificates: o.TotalCertificates,
		Certificates:      serializedCertificates,
	}
	return serializer
}

// -------------------------------------------------------------
type UpdateCAStatusOutputSerialized struct {
	CACertificateSerialized
}

func (o *UpdateCAStatusOutput) Serialize() UpdateCAStatusOutputSerialized {
	return UpdateCAStatusOutputSerialized{
		CACertificateSerialized: o.CACertificate.Serialize(),
	}
}

func (o *UpdateCAStatusOutputSerialized) Deserialize() UpdateCAStatusOutput {
	return UpdateCAStatusOutput{
		CACertificate: o.CACertificateSerialized.Deserialize(),
	}
}
