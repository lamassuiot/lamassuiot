package api

import (
	"time"
)

type SupportedKeyTypeInfoLogSerialized struct {
	Type        string `json:"type"`
	MinimumSize int    `json:"minimum_size"`
	MaximumSize int    `json:"maximum_size"`
}

func (s *SupportedKeyTypeInfo) ToSerializedLog() *SupportedKeyTypeInfoLogSerialized {
	return &SupportedKeyTypeInfoLogSerialized{
		Type:        string(s.Type),
		MinimumSize: s.MinimumSize,
		MaximumSize: s.MaximumSize,
	}
}

type EngineProviderInfoLogSerialized struct {
	Provider          string                              `json:"provider"`
	CryptokiVersion   string                              `json:"cryptoki_version"`
	Manufacturer      string                              `json:"manufacturer"`
	Model             string                              `json:"model"`
	Library           string                              `json:"library"`
	SupportedKeyTypes []SupportedKeyTypeInfoLogSerialized `json:"supported_key_types"`
}

func (e *EngineProviderInfo) ToSerializedLog() EngineProviderInfoLogSerialized {
	keys := make([]SupportedKeyTypeInfoLogSerialized, 0)
	for _, key := range e.SupportedKeyTypes {
		keys = append(keys, *key.ToSerializedLog())
	}

	serializer := EngineProviderInfoLogSerialized{
		Provider:          e.Provider,
		CryptokiVersion:   e.CryptokiVersion,
		Manufacturer:      e.Manufacturer,
		Model:             e.Model,
		Library:           e.Library,
		SupportedKeyTypes: keys,
	}
	return serializer
}

type SubjectLogSerialized struct {
	CommonName string `json:"common_name"`
}

func (o *Subject) ToSerializedLog() SubjectLogSerialized {
	serializer := SubjectLogSerialized{
		CommonName: o.CommonName,
	}
	return serializer
}

type CertificateLogSerialized struct {
	CAName       string               `json:"name"`
	Status       string               `json:"status"`
	SerialNumber string               `json:"serial_number"`
	Subject      SubjectLogSerialized `json:"subject"`
}

func (o *Certificate) ToSerializedLog() CertificateLogSerialized {
	serializer := CertificateLogSerialized{
		CAName:       o.CAName,
		Status:       string(o.Status),
		SerialNumber: o.SerialNumber,
		Subject:      o.Subject.ToSerializedLog(),
	}

	return serializer
}

type CACertificateLogSerialized struct {
	CertificateLogSerialized
}

func (o *CACertificate) ToSerializedLog() CACertificateLogSerialized {
	serializer := CACertificateLogSerialized{
		CertificateLogSerialized: o.Certificate.ToSerializedLog(),
	}
	return serializer
}

// -------------------------------------------------------------
type GetStatsOutputLogSerialized struct {
	IssuedCerts int       `json:"issued_certificates"`
	CAs         int       `json:"cas"`
	ScanDate    time.Time `json:"scan_date"`
}

func (o *GetStatsOutput) ToSerializedLog() GetStatsOutputLogSerialized {
	serializer := GetStatsOutputLogSerialized{
		IssuedCerts: o.IssuedCerts,
		CAs:         o.CAs,
		ScanDate:    o.ScanDate,
	}
	return serializer
}

// -------------------------------------------------------------

type CreateCAOutputLogSerialized struct {
	CACertificateLogSerialized
}

func (o *CreateCAOutput) ToSerializedLog() CreateCAOutputLogSerialized {
	serializer := CreateCAOutputLogSerialized{
		CACertificateLogSerialized: o.CACertificate.ToSerializedLog(),
	}
	return serializer
}

// -------------------------------------------------------------

type ImportCAOutputLogSerialized struct {
	CACertificateLogSerialized
}

func (o *ImportCAOutput) ToSerializedLog() ImportCAOutputLogSerialized {
	serializer := ImportCAOutputLogSerialized{
		CACertificateLogSerialized: o.CACertificate.ToSerializedLog(),
	}
	return serializer
}

// -------------------------------------------------------------

type GetCAsOutputLogSerialized struct {
	TotalCAs  int `json:"total_cas"`
	OutputCAs int `json:"output_cas"`
}

func (o *GetCAsOutput) ToSerializedLog() GetCAsOutputLogSerialized {
	serializer := GetCAsOutputLogSerialized{
		TotalCAs:  o.TotalCAs,
		OutputCAs: len(o.CAs),
	}
	return serializer
}

// -------------------------------------------------------------

type SignOutputLogSerialized struct {
	Signature        string         `json:"signature"`
	SigningAlgorithm SigningAlgType `json:"signing_algorithm"`
}

func (o *SignOutput) ToSerializedLog() SignOutputLogSerialized {
	serializer := SignOutputLogSerialized{
		Signature:        o.Signature,
		SigningAlgorithm: o.SigningAlgorithm,
	}
	return serializer
}

type VerifyOutputLogSerialized struct {
	VerificationResult bool `json:"verification"`
}

func (o *VerifyOutput) ToSerializedLog() VerifyOutputLogSerialized {
	serializer := VerifyOutputLogSerialized{
		VerificationResult: o.VerificationResult,
	}
	return serializer
}

// -------------------------------------------------------------
type GetCAByNameOutputLogSerialized struct {
	CACertificateLogSerialized
}

func (o *GetCAByNameOutput) ToSerializedLog() GetCAByNameOutputLogSerialized {
	return GetCAByNameOutputLogSerialized{
		CACertificateLogSerialized: o.CACertificate.ToSerializedLog(),
	}
}

// -------------------------------------------------------------
type RevokeCAOutputLogSerialized struct {
	CACertificateLogSerialized
}

func (o *RevokeCAOutput) ToSerializedLog() RevokeCAOutputLogSerialized {
	return RevokeCAOutputLogSerialized{
		CACertificateLogSerialized: o.CACertificate.ToSerializedLog(),
	}
}

// -------------------------------------------------------------
type SignCertificateRequestOutputLogSerialized struct {
	Certificate   string `json:"certificate"`
	CACertificate string `json:"ca_certificate"`
}

func (o *SignCertificateRequestOutput) ToSerializedLog() SignCertificateRequestOutputLogSerialized {
	return SignCertificateRequestOutputLogSerialized{
		Certificate:   o.Certificate.Subject.CommonName,
		CACertificate: o.CACertificate.Subject.CommonName,
	}
}

// -------------------------------------------------------------
type RevokeCertificateOutputLogSerialized struct {
	CertificateLogSerialized
}

func (o *RevokeCertificateOutput) ToSerializedLog() RevokeCertificateOutputLogSerialized {
	return RevokeCertificateOutputLogSerialized{
		CertificateLogSerialized: o.Certificate.ToSerializedLog(),
	}
}

// -------------------------------------------------------------

type UpdateCertificateStatusOutputLogSerialized struct {
	CertificateLogSerialized
}

func (o *UpdateCertificateStatusOutput) ToSerializedLog() UpdateCertificateStatusOutputLogSerialized {
	return UpdateCertificateStatusOutputLogSerialized{
		CertificateLogSerialized: o.Certificate.ToSerializedLog(),
	}
}

// -------------------------------------------------------------
type GetCertificateBySerialNumberOutputLogSerialized struct {
	CertificateLogSerialized
}

func (o *GetCertificateBySerialNumberOutput) ToSerializedLog() GetCertificateBySerialNumberOutputLogSerialized {
	return GetCertificateBySerialNumberOutputLogSerialized{
		CertificateLogSerialized: o.Certificate.ToSerializedLog(),
	}
}

// -------------------------------------------------------------
type GetCertificatesOutputLogSerialized struct {
	TotalCertificates  int `json:"total_certificates"`
	OutputCertificates int `json:"output_certificates"`
}

func (o *GetCertificatesOutput) ToSerializedLog() GetCertificatesOutputLogSerialized {
	serializer := GetCertificatesOutputLogSerialized{
		TotalCertificates:  o.TotalCertificates,
		OutputCertificates: len(o.Certificates),
	}
	return serializer
}

// -------------------------------------------------------------
type UpdateCAStatusOutputLogSerialized struct {
	CACertificateLogSerialized
}

func (o *UpdateCAStatusOutput) ToSerializedLog() UpdateCAStatusOutputLogSerialized {
	return UpdateCAStatusOutputLogSerialized{
		CACertificateLogSerialized: o.CACertificate.ToSerializedLog(),
	}
}

// -------------------------------------------------------------
type GetExpiredAndOutOfSyncCertificatesOutputLogSerialized struct {
	ExpiredCount int `json:"certificates_expired_count"`
}

func (o *GetExpiredAndOutOfSyncCertificatesOutput) ToSerializedLog() GetExpiredAndOutOfSyncCertificatesOutputLogSerialized {
	return GetExpiredAndOutOfSyncCertificatesOutputLogSerialized{
		ExpiredCount: o.TotalCertificates,
	}
}

// -------------------------------------------------------------
type GetCertificatesAboutToExpireOutputLogSerialized struct {
	AboutToExpireCount int `json:"certificates_expired_count"`
}

func (o *GetCertificatesAboutToExpireOutput) ToSerializedLog() GetCertificatesAboutToExpireOutputLogSerialized {
	return GetCertificatesAboutToExpireOutputLogSerialized{
		AboutToExpireCount: o.TotalCertificates,
	}
}
