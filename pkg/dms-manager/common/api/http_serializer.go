package api

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"

	"github.com/lib/pq"
)

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

type X509AssetSerialized struct {
	Certificate        string `json:"certificate,omitempty"`
	CertificateRequest string `json:"certificate_request,omitempty"`
}

func (o *X509Asset) Serialize() string {
	if o.Certificate != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: o.Certificate.Raw})
		certEnc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(certEnc, pemCert)
		return string(certEnc)
	}

	if o.CertificateRequest != nil {
		pemCertRequest := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: o.CertificateRequest.Raw})
		certRequestEnc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCertRequest)))
		base64.StdEncoding.Encode(certRequestEnc, pemCertRequest)
		return string(certRequestEnc)
	}

	return ""
}

func DeserializeX509Asset(certificateAsset string, certificateRequestAsset string) X509Asset {
	var certificate *x509.Certificate = nil
	decodedCert, err := base64.StdEncoding.DecodeString(certificateAsset)
	if err == nil {
		certBlock, _ := pem.Decode([]byte(decodedCert))
		if certBlock != nil {
			crt, err := x509.ParseCertificate(certBlock.Bytes)
			if err == nil {
				certificate = crt
			}
		}
	}

	var certificateRequest *x509.CertificateRequest = nil
	decodedCertRequest, err := base64.StdEncoding.DecodeString(certificateRequestAsset)
	if err == nil {
		certRequestBlock, _ := pem.Decode([]byte(decodedCertRequest))
		if certRequestBlock != nil {
			csr, err := x509.ParseCertificateRequest(certRequestBlock.Bytes)
			if err == nil {
				certificateRequest = csr
			}
		}
	}

	serializer := X509Asset{
		IsCertificate:      certificate != nil,
		Certificate:        certificate,
		CertificateRequest: certificateRequest,
	}
	return serializer
}

type DeviceManufacturingServiceSerialized struct {
	Name                      string                        `json:"name"`
	Status                    DMSStatus                     `json:"status"`
	SerialNumber              string                        `json:"serial_number"`
	KeyMetadata               KeyStrengthMetadataSerialized `json:"key_metadata"`
	Subject                   SubjectSerialized             `json:"subject"`
	AuthorizedCAs             []string                      `json:"authorized_cas"`
	CreationTimestamp         int                           `json:"creation_timestamp"`
	LastStatusUpdateTimestamp int                           `json:"last_status_update_timestamp"`
	Certificate               string                        `json:"certificate,omitempty"`
	CertificateRequest        string                        `json:"certificate_request,omitempty"`
}

func (o *DeviceManufacturingService) Serialize() DeviceManufacturingServiceSerialized {
	serializer := DeviceManufacturingServiceSerialized{
		Name:          o.Name,
		Status:        o.Status,
		SerialNumber:  o.SerialNumber,
		KeyMetadata:   o.KeyMetadata.Serialize(),
		Subject:       o.Subject.Serialize(),
		AuthorizedCAs: o.AuthorizedCAs,
	}

	if o.X509Asset.IsCertificate {
		serializer.Certificate = o.X509Asset.Serialize()
	} else {
		serializer.CertificateRequest = o.X509Asset.Serialize()
	}

	if o.CreationTimestamp.Valid {
		serializer.CreationTimestamp = int(o.CreationTimestamp.Time.UnixMilli())
	}

	if o.CreationTimestamp.Valid {
		serializer.LastStatusUpdateTimestamp = int(o.LastStatusUpdateTimestamp.Time.UnixMilli())
	}
	return serializer
}

func (o *DeviceManufacturingServiceSerialized) Deserialize() DeviceManufacturingService {
	serializer := DeviceManufacturingService{
		Name:          o.Name,
		Status:        o.Status,
		SerialNumber:  o.SerialNumber,
		KeyMetadata:   o.KeyMetadata.Deserialize(),
		Subject:       o.Subject.Deserialize(),
		AuthorizedCAs: o.AuthorizedCAs,
		X509Asset:     DeserializeX509Asset(o.Certificate, o.CertificateRequest),
	}

	if o.CreationTimestamp > 0 {
		serializer.CreationTimestamp = pq.NullTime{
			Time:  time.UnixMilli(int64(o.CreationTimestamp)),
			Valid: true,
		}
	} else {
		serializer.CreationTimestamp = pq.NullTime{
			Valid: false,
		}
	}

	if o.LastStatusUpdateTimestamp > 0 {
		serializer.LastStatusUpdateTimestamp = pq.NullTime{
			Time:  time.UnixMilli(int64(o.LastStatusUpdateTimestamp)),
			Valid: true,
		}
	} else {
		serializer.LastStatusUpdateTimestamp = pq.NullTime{
			Valid: false,
		}
	}
	return serializer
}

// -------------------------------------------------------------

type GetDMSByNameOutputSerialized struct {
	DeviceManufacturingServiceSerialized
}

func (o *GetDMSByNameOutput) Serialize() GetDMSByNameOutputSerialized {
	serializer := GetDMSByNameOutputSerialized{
		DeviceManufacturingServiceSerialized: o.DeviceManufacturingService.Serialize(),
	}
	return serializer
}

func (o *GetDMSByNameOutputSerialized) Deserialize() GetDMSByNameOutput {
	serializer := GetDMSByNameOutput{
		DeviceManufacturingService: o.DeviceManufacturingServiceSerialized.Deserialize(),
	}
	return serializer
}

// ----------------------------------------------

type GetDMSsOutputSerialized struct {
	TotalDMSs int                                    `json:"total_dmss"`
	DMSs      []DeviceManufacturingServiceSerialized `json:"dmss"`
}

func (o *GetDMSsOutput) Serialize() GetDMSsOutputSerialized {
	serializer := GetDMSsOutputSerialized{
		TotalDMSs: o.TotalDMSs,
		DMSs:      make([]DeviceManufacturingServiceSerialized, len(o.DMSs)),
	}
	for i, dms := range o.DMSs {
		serializer.DMSs[i] = dms.Serialize()
	}
	return serializer
}

func (o *GetDMSsOutputSerialized) Deserialize() GetDMSsOutput {
	serializer := GetDMSsOutput{
		TotalDMSs: o.TotalDMSs,
		DMSs:      make([]DeviceManufacturingService, len(o.DMSs)),
	}
	for i, dms := range o.DMSs {
		serializer.DMSs[i] = dms.Deserialize()
	}
	return serializer
}

// ----------------------------------------------

type CreateDMSWithCertificateRequestOutputSerialized struct {
	DeviceManufacturingServiceSerialized
}

func (o *CreateDMSWithCertificateRequestOutput) Serialize() CreateDMSWithCertificateRequestOutputSerialized {
	serializer := CreateDMSWithCertificateRequestOutputSerialized{
		DeviceManufacturingServiceSerialized: o.DeviceManufacturingService.Serialize(),
	}
	return serializer
}

func (o *CreateDMSWithCertificateRequestOutputSerialized) Deserialize() CreateDMSWithCertificateRequestOutput {
	serializer := CreateDMSWithCertificateRequestOutput{
		DeviceManufacturingService: o.DeviceManufacturingServiceSerialized.Deserialize(),
	}
	return serializer
}

// ----------------------------------------------

type CreateDMSOutputSerialized struct {
	DMS        DeviceManufacturingServiceSerialized `json:"dms"`
	PrivateKey string                               `json:"private_key"`
}

func (o *CreateDMSOutput) Serialize() CreateDMSOutputSerialized {
	key := ""
	if o.DMS.KeyMetadata.KeyType == RSA {
		if rsaKey, ok := o.PrivateKey.(*rsa.PrivateKey); ok {
			rsaBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
			pemEncodedKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: rsaBytes})
			b64PemEncodedKey := base64.StdEncoding.EncodeToString(pemEncodedKey)
			key = b64PemEncodedKey
		}
	} else if o.DMS.KeyMetadata.KeyType == ECDSA {
		if ecdsaKey, ok := o.PrivateKey.(*ecdsa.PrivateKey); ok {
			ecdsaBytes, err := x509.MarshalECPrivateKey(ecdsaKey)
			if err == nil {
				pemEncodedKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaBytes})
				b64PemEncodedKey := base64.StdEncoding.EncodeToString(pemEncodedKey)
				key = b64PemEncodedKey
			}
		}
	}

	serializer := CreateDMSOutputSerialized{
		DMS:        o.DMS.Serialize(),
		PrivateKey: key,
	}
	return serializer
}

func (o *CreateDMSOutputSerialized) Deserialize() CreateDMSOutput {
	serializer := CreateDMSOutput{
		DMS:        o.DMS.Deserialize(),
		PrivateKey: o.PrivateKey,
	}
	return serializer
}

// ----------------------------------------------

type UpdateDMSStatusOutputSerialized struct {
	DeviceManufacturingServiceSerialized
}

func (o *UpdateDMSStatusOutput) Serialize() UpdateDMSStatusOutputSerialized {
	serializer := UpdateDMSStatusOutputSerialized{
		DeviceManufacturingServiceSerialized: o.DeviceManufacturingService.Serialize(),
	}
	return serializer
}

func (o *UpdateDMSStatusOutputSerialized) Deserialize() UpdateDMSStatusOutput {
	serializer := UpdateDMSStatusOutput{
		DeviceManufacturingService: o.DeviceManufacturingServiceSerialized.Deserialize(),
	}
	return serializer
}

// ----------------------------------------------

type UpdateDMSAuthorizedCAsOutputSerialized struct {
	DeviceManufacturingServiceSerialized
}

func (o *UpdateDMSAuthorizedCAsOutput) Serialize() UpdateDMSAuthorizedCAsOutputSerialized {
	serializer := UpdateDMSAuthorizedCAsOutputSerialized{
		DeviceManufacturingServiceSerialized: o.DeviceManufacturingService.Serialize(),
	}
	return serializer
}

func (o *UpdateDMSAuthorizedCAsOutputSerialized) Deserialize() UpdateDMSAuthorizedCAsOutput {
	serializer := UpdateDMSAuthorizedCAsOutput{
		DeviceManufacturingService: o.DeviceManufacturingServiceSerialized.Deserialize(),
	}
	return serializer
}
