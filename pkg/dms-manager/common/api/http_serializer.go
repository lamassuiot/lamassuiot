package api

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/utils"
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

func SerializeCRT(crt *x509.Certificate) string {
	if crt != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})
		certEnc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(certEnc, pemCert)
		return string(certEnc)
	}

	return ""
}

func SerializeCSR(csr *x509.CertificateRequest) string {
	if csr != nil {
		pemCertRequest := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
		certRequestEnc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCertRequest)))
		base64.StdEncoding.Encode(certRequestEnc, pemCertRequest)
		return string(certRequestEnc)
	}

	return ""
}

func DeserializeCSR(certificateRequestString string) *x509.CertificateRequest {
	var certificateRequest *x509.CertificateRequest = nil
	decodedCertRequest, err := base64.StdEncoding.DecodeString(certificateRequestString)
	if err == nil {
		certRequestBlock, _ := pem.Decode([]byte(decodedCertRequest))
		if certRequestBlock != nil {
			csr, err := x509.ParseCertificateRequest(certRequestBlock.Bytes)
			if err == nil {
				certificateRequest = csr
			}
		}
	}

	return certificateRequest
}

func DeserializeCRT(certificateString string) *x509.Certificate {
	var certificate *x509.Certificate = nil
	decodedCert, err := base64.StdEncoding.DecodeString(certificateString)
	if err == nil {
		certBlock, _ := pem.Decode([]byte(decodedCert))
		if certBlock != nil {
			crt, err := x509.ParseCertificate(certBlock.Bytes)
			if err == nil {
				certificate = crt
			}
		}
	}

	return certificate
}

type RemoteAccessIdentitySerialized struct {
	SerialNumber          string                        `json:"serial_number"`
	KeyMetadata           KeyStrengthMetadataSerialized `json:"key_metadata"`
	Subject               SubjectSerialized             `json:"subject"`
	AuthorizedCAs         []string                      `json:"authorized_cas"`
	ExternalKeyGeneration bool                          `json:"external_key_generation"`
	Certificate           string                        `json:"certificate,omitempty"`
	CertificateRequest    string                        `json:"certificate_request,omitempty"`
}

func (o *RemoteAccessIdentity) Serialize() RemoteAccessIdentitySerialized {
	return RemoteAccessIdentitySerialized{
		ExternalKeyGeneration: o.ExternalKeyGeneration,
		SerialNumber:          o.SerialNumber,
		KeyMetadata:           o.KeyMetadata.Serialize(),
		Subject:               o.Subject.Serialize(),
		AuthorizedCAs:         o.AuthorizedCAs,
		Certificate:           SerializeCRT(o.Certificate),
		CertificateRequest:    SerializeCSR(o.CertificateRequest),
	}
}

func (o RemoteAccessIdentitySerialized) Deserialize() *RemoteAccessIdentity {
	return &RemoteAccessIdentity{
		ExternalKeyGeneration: o.ExternalKeyGeneration,
		SerialNumber:          o.SerialNumber,
		KeyMetadata:           o.KeyMetadata.Deserialize(),
		Subject:               o.Subject.Deserialize(),
		AuthorizedCAs:         o.AuthorizedCAs,
		Certificate:           DeserializeCRT(o.Certificate),
		CertificateRequest:    DeserializeCSR(o.CertificateRequest),
	}
}

type IdentityProfileGeneralSettingsSerialized struct {
	EnrollmentMode EnrollmentMode `json:"enrollment_mode"`
}

func (o *IdentityProfileGeneralSettings) Serialize() IdentityProfileGeneralSettingsSerialized {
	return IdentityProfileGeneralSettingsSerialized{
		EnrollmentMode: o.EnrollmentMode,
	}
}

func (o *IdentityProfileGeneralSettingsSerialized) Deserialize() IdentityProfileGeneralSettings {
	return IdentityProfileGeneralSettings{
		EnrollmentMode: o.EnrollmentMode,
	}
}

type IdentityProfileEnrollmentSettingsSerialized struct {
	AuthenticationMode     ESTAuthenticationMode `json:"authentication_mode"`
	AllowNewAutoEnrollment bool                  `json:"allow_new_auto_enrollment"`
	Tags                   []string              `json:"tags"`
	Icon                   string                `json:"icon"`
	Color                  string                `json:"color"`
	AuthorizedCA           string                `json:"authorized_ca"`
	BootstrapCAs           []string              `json:"bootstrap_cas"`
}

func (o *IdentityProfileEnrollmentSettings) Serialize() IdentityProfileEnrollmentSettingsSerialized {
	return IdentityProfileEnrollmentSettingsSerialized{
		AuthenticationMode:     o.AuthenticationMode,
		AllowNewAutoEnrollment: o.AllowNewAutoEnrollment,
		Tags:                   o.Tags,
		Icon:                   o.Icon,
		Color:                  o.Color,
		AuthorizedCA:           o.AuthorizedCA,
		BootstrapCAs:           o.BootstrapCAs,
	}
}

func (o *IdentityProfileEnrollmentSettingsSerialized) Deserialize() IdentityProfileEnrollmentSettings {
	return IdentityProfileEnrollmentSettings{
		AuthenticationMode:     o.AuthenticationMode,
		AllowNewAutoEnrollment: o.AllowNewAutoEnrollment,
		Tags:                   o.Tags,
		Icon:                   o.Icon,
		Color:                  o.Color,
		AuthorizedCA:           o.AuthorizedCA,
		BootstrapCAs:           o.BootstrapCAs,
	}
}

type IdentityProfileReenrollmentSettingsSerialized struct {
	AllowExpiredRenewal       bool   `json:"allow_expired_renewal"`
	PreventiveRenewalInterval string `json:"preventive_renewal_interval"`
}

func (o *IdentityProfileReenrollmentSettings) Serialize() IdentityProfileReenrollmentSettingsSerialized {
	return IdentityProfileReenrollmentSettingsSerialized{
		AllowExpiredRenewal:       o.AllowExpiredRenewal,
		PreventiveRenewalInterval: utils.ShortDuration(o.PreventiveRenewalInterval),
	}
}

func (o IdentityProfileReenrollmentSettingsSerialized) Deserialize() IdentityProfileReenrollmentSettings {
	duration := time.Duration(-1 * time.Second)
	duration, _ = time.ParseDuration(o.PreventiveRenewalInterval)

	return IdentityProfileReenrollmentSettings{
		AllowExpiredRenewal:       o.AllowExpiredRenewal,
		PreventiveRenewalInterval: duration,
	}
}

type AwsSpecificationSerialized struct {
	ShadowType string `json:"shadow_type"`
}

func (o *AwsSpecification) Serialize() AwsSpecificationSerialized {
	serializer := AwsSpecificationSerialized{
		ShadowType: string(o.ShadowType),
	}
	return serializer
}

func (o *AwsSpecificationSerialized) Deserialize() AwsSpecification {
	serializer := AwsSpecification{
		ShadowType: ParseShadowType(o.ShadowType),
	}
	return serializer
}

type StaticCASerialized struct {
	ID          string `json:"id"`
	Certificate string `json:"certificate"`
}

func (o *StaticCA) Serialize() StaticCASerialized {
	return StaticCASerialized{
		ID:          o.ID,
		Certificate: SerializeCRT(o.Certificate),
	}
}

func (o StaticCASerialized) Deserialize() StaticCA {
	return StaticCA{
		ID:          o.ID,
		Certificate: DeserializeCRT(o.Certificate),
	}
}

type IdentityProfileCADistributionSettingsSerialized struct {
	IncludeAuthorizedCA        bool                 `json:"include_authorized_ca"`
	IncludeBootstrapCAs        bool                 `json:"include_bootstrap_cas"`
	IncludeLamassuDownstreamCA bool                 `json:"include_lamassu_downstream_ca"`
	ManagedCAs                 []string             `json:"managed_cas"`
	StaticCAs                  []StaticCASerialized `json:"static_cas"`
}

func (o *IdentityProfileCADistributionSettings) Serialize() IdentityProfileCADistributionSettingsSerialized {
	cas := []StaticCASerialized{}
	for _, ca := range o.StaticCAs {
		cas = append(cas, ca.Serialize())
	}

	return IdentityProfileCADistributionSettingsSerialized{
		IncludeAuthorizedCA:        o.IncludeAuthorizedCA,
		IncludeBootstrapCAs:        o.IncludeBootstrapCAs,
		IncludeLamassuDownstreamCA: o.IncludeLamassuDownstreamCA,
		ManagedCAs:                 o.ManagedCAs,
		StaticCAs:                  cas,
	}
}

func (o IdentityProfileCADistributionSettingsSerialized) Deserialize() IdentityProfileCADistributionSettings {
	cas := []StaticCA{}
	for _, ca := range o.StaticCAs {
		cas = append(cas, ca.Deserialize())
	}

	return IdentityProfileCADistributionSettings{
		IncludeAuthorizedCA:        o.IncludeAuthorizedCA,
		IncludeBootstrapCAs:        o.IncludeBootstrapCAs,
		IncludeLamassuDownstreamCA: o.IncludeLamassuDownstreamCA,
		ManagedCAs:                 o.ManagedCAs,
		StaticCAs:                  cas,
	}
}

type IdentityProfileSerialized struct {
	GeneralSettings        IdentityProfileGeneralSettingsSerialized        `json:"general_setting"`
	EnrollmentSettings     IdentityProfileEnrollmentSettingsSerialized     `json:"enrollment_settings"`
	ReerollmentSettings    IdentityProfileReenrollmentSettingsSerialized   `json:"reenrollment_settings"`
	CADistributionSettings IdentityProfileCADistributionSettingsSerialized `json:"ca_distribution_settings"`
	PublishToAWS           bool                                            `json:"aws_iotcore_publish"`
}

func (o *IdentityProfile) Serialize() IdentityProfileSerialized {
	return IdentityProfileSerialized{
		GeneralSettings:        o.GeneralSettings.Serialize(),
		EnrollmentSettings:     o.EnrollmentSettings.Serialize(),
		ReerollmentSettings:    o.ReerollmentSettings.Serialize(),
		CADistributionSettings: o.CADistributionSettings.Serialize(),
		PublishToAWS:           o.PublishToAWS,
	}
}

func (o IdentityProfileSerialized) Deserialize() *IdentityProfile {
	return &IdentityProfile{
		GeneralSettings:        o.GeneralSettings.Deserialize(),
		EnrollmentSettings:     o.EnrollmentSettings.Deserialize(),
		ReerollmentSettings:    o.ReerollmentSettings.Deserialize(),
		CADistributionSettings: o.CADistributionSettings.Deserialize(),
		PublishToAWS:           o.PublishToAWS,
	}
}

type DeviceManufacturingServiceSerialized struct {
	Name                 string                          `json:"name"`
	Status               DMSStatus                       `json:"status"`
	CloudDMS             bool                            `json:"cloud_dms"`
	Aws                  AwsSpecificationSerialized      `json:"aws"`
	CreationTimestamp    int                             `json:"creation_timestamp"`
	RemoteAccessIdentity *RemoteAccessIdentitySerialized `json:"remote_access_identity,omitempty"`
	IdentityProfile      *IdentityProfileSerialized      `json:"identity_profile,omitempty"`
}

func (o *DeviceManufacturingService) Serialize() DeviceManufacturingServiceSerialized {
	serializer := DeviceManufacturingServiceSerialized{
		Name:              o.Name,
		Status:            o.Status,
		CloudDMS:          o.CloudDMS,
		Aws:               o.Aws.Serialize(),
		CreationTimestamp: int(o.CreationTimestamp.UnixMilli()),
	}

	if o.RemoteAccessIdentity != nil {
		rais := o.RemoteAccessIdentity.Serialize()
		serializer.RemoteAccessIdentity = &rais
	}

	if o.IdentityProfile != nil {
		ids := o.IdentityProfile.Serialize()
		serializer.IdentityProfile = &ids
	}

	return serializer
}

func (o *DeviceManufacturingServiceSerialized) Deserialize() DeviceManufacturingService {
	serializer := DeviceManufacturingService{
		Name:              o.Name,
		Status:            o.Status,
		CloudDMS:          o.CloudDMS,
		Aws:               o.Aws.Deserialize(),
		CreationTimestamp: time.UnixMilli(int64(o.CreationTimestamp)),
	}

	if o.RemoteAccessIdentity != nil {
		serializer.RemoteAccessIdentity = o.RemoteAccessIdentity.Deserialize()
	}

	if o.IdentityProfile != nil {
		serializer.IdentityProfile = o.IdentityProfile.Deserialize()
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

type CreateDMSOutputSerialized struct {
	DMS        DeviceManufacturingServiceSerialized `json:"dms"`
	PrivateKey string                               `json:"private_key,omitempty"`
}

func (o *CreateDMSOutput) Serialize() CreateDMSOutputSerialized {
	key := ""
	if !o.DMS.CloudDMS {
		if o.DMS.RemoteAccessIdentity.KeyMetadata.KeyType == RSA {
			if rsaKey, ok := o.PrivateKey.(*rsa.PrivateKey); ok {
				rsaBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
				pemEncodedKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: rsaBytes})
				b64PemEncodedKey := base64.StdEncoding.EncodeToString(pemEncodedKey)
				key = b64PemEncodedKey
			}
		} else if o.DMS.RemoteAccessIdentity.KeyMetadata.KeyType == ECDSA {
			if ecdsaKey, ok := o.PrivateKey.(*ecdsa.PrivateKey); ok {
				ecdsaBytes, err := x509.MarshalECPrivateKey(ecdsaKey)
				if err == nil {
					pemEncodedKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaBytes})
					b64PemEncodedKey := base64.StdEncoding.EncodeToString(pemEncodedKey)
					key = b64PemEncodedKey
				}
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
