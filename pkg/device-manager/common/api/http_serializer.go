package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"

	"github.com/lib/pq"
)

type SlotsStatsSerialized struct {
	PendingEnrollment int `json:"pending_enrollment"`
	Active            int `json:"active"`
	Expired           int `json:"expired"`
	Revoked           int `json:"revoked"`
}

func (s *SlotsStats) Serialize() SlotsStatsSerialized {
	return SlotsStatsSerialized{
		PendingEnrollment: s.PendingEnrollment,
		Active:            s.Active,
		Expired:           s.Expired,
		Revoked:           s.Revoked,
	}
}

func (s *SlotsStatsSerialized) Deserialize() SlotsStats {
	return SlotsStats{
		PendingEnrollment: s.PendingEnrollment,
		Active:            s.Active,
		Expired:           s.Expired,
		Revoked:           s.Revoked,
	}
}

type DevicesStatsSerialized struct {
	PendingProvisioning     int `json:"pending_provisioning"`
	FullyProvisioned        int `json:"fully_provisioned"`
	PartiallyProvisioned    int `json:"partially_provisioned"`
	ProvisionedWithWarnings int `json:"provisioned_with_warnings"`
	Decommisioned           int `json:"decommisioned"`
}

func (s *DevicesStats) Serialize() DevicesStatsSerialized {
	return DevicesStatsSerialized{
		PendingProvisioning:     s.PendingProvisioning,
		FullyProvisioned:        s.FullyProvisioned,
		PartiallyProvisioned:    s.PartiallyProvisioned,
		ProvisionedWithWarnings: s.ProvisionedWithWarnings,
		Decommisioned:           s.Decommisioned,
	}
}

func (s *DevicesStatsSerialized) Deserialize() DevicesStats {
	return DevicesStats{
		PendingProvisioning:     s.PendingProvisioning,
		FullyProvisioned:        s.FullyProvisioned,
		PartiallyProvisioned:    s.PartiallyProvisioned,
		ProvisionedWithWarnings: s.ProvisionedWithWarnings,
		Decommisioned:           s.Decommisioned,
	}
}

type DevicesManagerStatsSerialized struct {
	DevicesStats DevicesStats `json:"devices_stats"`
	SlotsStats   SlotsStats   `json:"slots_stats"`
}

func (s *DevicesManagerStats) Serialize() DevicesManagerStatsSerialized {
	return DevicesManagerStatsSerialized{
		DevicesStats: s.DevicesStats,
		SlotsStats:   s.SlotsStats,
	}
}

func (s *DevicesManagerStatsSerialized) Deserialize() DevicesManagerStats {
	return DevicesManagerStats{
		DevicesStats: s.DevicesStats,
		SlotsStats:   s.SlotsStats,
	}
}

type KeyStrengthMetadataSerialized struct {
	KeyType     KeyType     `json:"key_type"`
	KeyBits     int         `json:"key_bits"`
	KeyStrength KeyStrength `json:"key_strength"`
}

func (s *KeyStrengthMetadata) Serialize() KeyStrengthMetadataSerialized {
	return KeyStrengthMetadataSerialized{
		KeyType:     s.KeyType,
		KeyBits:     s.KeyBits,
		KeyStrength: s.KeyStrength,
	}
}

func (s *KeyStrengthMetadataSerialized) Deserialize() KeyStrengthMetadata {
	return KeyStrengthMetadata{
		KeyType:     s.KeyType,
		KeyBits:     s.KeyBits,
		KeyStrength: s.KeyStrength,
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

func (s *Subject) Serialize() SubjectSerialized {
	return SubjectSerialized{
		CommonName:       s.CommonName,
		Organization:     s.Organization,
		OrganizationUnit: s.OrganizationUnit,
		Country:          s.Country,
		State:            s.State,
		Locality:         s.Locality,
	}
}

func (s *SubjectSerialized) Deserialize() Subject {
	return Subject{
		CommonName:       s.CommonName,
		Organization:     s.Organization,
		OrganizationUnit: s.OrganizationUnit,
		Country:          s.Country,
		State:            s.State,
		Locality:         s.Locality,
	}
}

type CertificateSerialized struct {
	CAName              string                        `json:"ca_name"`
	SerialNumber        string                        `json:"serial_number"`
	Certificate         string                        `json:"certificate"`
	Status              CertificateStatus             `json:"status"`
	KeyMetadata         KeyStrengthMetadataSerialized `json:"key_metadata"`
	Subject             SubjectSerialized             `json:"subject"`
	ValidFrom           int                           `json:"valid_from"`
	ValidTo             int                           `json:"valid_to"`
	RevocationTimestamp int                           `json:"revocation_timestamp,omitempty"`
	RevocationReason    string                        `json:"revocation_reason,omitempty"`
}

func (s *Certificate) Serialize() CertificateSerialized {
	var certificateString string = ""
	if s.Certificate != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate.Raw})
		certEnc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(certEnc, pemCert)
		certificateString = string(certEnc)
	}

	serializer := CertificateSerialized{
		CAName:           s.CAName,
		SerialNumber:     s.SerialNumber,
		Certificate:      certificateString,
		Status:           s.Status,
		KeyMetadata:      s.KeyMetadata.Serialize(),
		Subject:          s.Subject.Serialize(),
		ValidFrom:        int(s.ValidFrom.Unix()),
		ValidTo:          int(s.ValidTo.Unix()),
		RevocationReason: s.RevocationReason,
	}

	if s.RevocationTimestamp.Valid {
		serializer.RevocationTimestamp = int(s.RevocationTimestamp.Time.Unix())
	}

	return serializer
}

func (s *CertificateSerialized) Deserialize() Certificate {
	var certificate *x509.Certificate = nil

	decodedCert, err := base64.StdEncoding.DecodeString(s.Certificate)
	if err == nil {
		certBlock, _ := pem.Decode([]byte(decodedCert))
		if certBlock != nil {
			certificate, _ = x509.ParseCertificate(certBlock.Bytes)
		}
	}

	serializer := Certificate{
		CAName:       s.CAName,
		Status:       ParseCertificateStatus(string(s.Status)),
		SerialNumber: s.SerialNumber,
		ValidFrom:    time.Unix(int64(s.ValidFrom), 0),
		ValidTo:      time.Unix(int64(s.ValidTo), 0),
		KeyMetadata:  s.KeyMetadata.Deserialize(),
		Subject:      s.Subject.Deserialize(),
		Certificate:  certificate,
	}

	if s.RevocationTimestamp > 0 {
		serializer.RevocationTimestamp = pq.NullTime{
			Time:  time.Unix(int64(s.RevocationTimestamp), 0),
			Valid: true,
		}
		serializer.RevocationReason = s.RevocationReason
	} else {
		serializer.RevocationTimestamp = pq.NullTime{
			Valid: false,
		}
	}

	return serializer
}

type SlotSerialized struct {
	ID                  string                  `json:"id"`
	ActiveCertificate   CertificateSerialized   `json:"active_certificate"`
	ArchiveCertificates []CertificateSerialized `json:"archive_certificates"`
}

func (s *Slot) Serialize() SlotSerialized {
	var archiveCertificates []CertificateSerialized
	for _, cert := range s.ArchiveCertificates {
		archiveCertificates = append(archiveCertificates, cert.Serialize())
	}
	return SlotSerialized{
		ID:                  s.ID,
		ActiveCertificate:   s.ActiveCertificate.Serialize(),
		ArchiveCertificates: archiveCertificates,
	}
}

func (s *SlotSerialized) Deserialize() Slot {
	deserializedActiveSlot := s.ActiveCertificate.Deserialize()
	var archiveCertificates []*Certificate
	for _, cert := range s.ArchiveCertificates {
		deserializedCert := cert.Deserialize()
		archiveCertificates = append(archiveCertificates, &deserializedCert)
	}
	return Slot{
		ID:                  s.ID,
		ActiveCertificate:   &deserializedActiveSlot,
		ArchiveCertificates: archiveCertificates,
	}
}

type DeviceSerialized struct {
	ID          string           `json:"id"`
	Alias       string           `json:"alias"`
	Status      DeviceStatus     `json:"status"`
	Slots       []SlotSerialized `json:"slots"`
	Description string           `json:"description"`
	Tags        []string         `json:"tags"`
	IconName    string           `json:"icon_name"`
	IconColor   string           `json:"icon_color"`
}

func (s *Device) Serialize() DeviceSerialized {
	var slots []SlotSerialized
	for _, slot := range s.Slots {
		serializedSlot := slot.Serialize()
		slots = append(slots, serializedSlot)
	}
	return DeviceSerialized{
		ID:          s.ID,
		Alias:       s.Alias,
		Status:      s.Status,
		Slots:       slots,
		Description: s.Description,
		Tags:        s.Tags,
		IconName:    s.IconName,
		IconColor:   s.IconColor,
	}
}

func (s *DeviceSerialized) Deserialize() Device {
	var slots []*Slot
	for _, slot := range s.Slots {
		deserializedSlot := slot.Deserialize()
		slots = append(slots, &deserializedSlot)
	}

	return Device{
		ID:          s.ID,
		Alias:       s.Alias,
		Status:      s.Status,
		Slots:       slots,
		Description: s.Description,
		Tags:        s.Tags,
		IconName:    s.IconName,
		IconColor:   s.IconColor,
	}
}

type DeviceLogSerialized struct {
	ID         string `json:"id"`
	DeviceID   string `json:"device_id"`
	LogType    string `json:"log_type"`
	LogMessage string `json:"log_message"`
	Timestamp  int    `json:"timestamp"`
}

func (s *DeviceLog) Serialize() DeviceLogSerialized {
	return DeviceLogSerialized{
		ID:         s.ID,
		DeviceID:   s.DeviceID,
		LogType:    s.LogType,
		LogMessage: s.LogMessage,
		Timestamp:  int(s.Timestamp.Unix()),
	}
}

func (s *DeviceLogSerialized) Deserialize() DeviceLog {
	return DeviceLog{
		ID:         s.ID,
		DeviceID:   s.DeviceID,
		LogType:    s.LogType,
		LogMessage: s.LogMessage,
		Timestamp:  time.Unix(int64(s.Timestamp), 0),
	}
}

// ---------------------------------------------------------------------

type GetStatsOutputSerialized struct {
	DevicesManagerStatsSerialized
}

func (s *GetStatsOutput) Serialize() GetStatsOutputSerialized {
	return GetStatsOutputSerialized{
		DevicesManagerStatsSerialized: s.DevicesManagerStats.Serialize(),
	}
}

func (s *GetStatsOutputSerialized) Deserialize() GetStatsOutput {
	return GetStatsOutput{
		DevicesManagerStats: s.DevicesManagerStatsSerialized.Deserialize(),
	}
}

// ---------------------------------------------------------------------

type CreateDeviceOutputSerialized struct {
	DeviceSerialized
}

func (s *CreateDeviceOutput) Serialize() CreateDeviceOutputSerialized {
	return CreateDeviceOutputSerialized{
		DeviceSerialized: s.Device.Serialize(),
	}
}

func (s *CreateDeviceOutputSerialized) Deserialize() CreateDeviceOutput {
	return CreateDeviceOutput{
		Device: s.DeviceSerialized.Deserialize(),
	}
}

// ---------------------------------------------------------------------

type UpdateDeviceMetadataOutputSerialized struct {
	DeviceSerialized
}

func (s *UpdateDeviceMetadataOutput) Serialize() UpdateDeviceMetadataOutputSerialized {
	return UpdateDeviceMetadataOutputSerialized{
		DeviceSerialized: s.Device.Serialize(),
	}
}

func (s *UpdateDeviceMetadataOutputSerialized) Deserialize() UpdateDeviceMetadataOutput {
	return UpdateDeviceMetadataOutput{
		Device: s.DeviceSerialized.Deserialize(),
	}
}

// ---------------------------------------------------------------------

type GetDevicesOutputSerialized struct {
	TotalDevices Device             `json:"total_devices"`
	Devices      []DeviceSerialized `json:"devices"`
}

func (s *GetDevicesOutput) Serialize() GetDevicesOutputSerialized {
	var devices []DeviceSerialized
	for _, device := range s.Devices {
		devices = append(devices, device.Serialize())
	}

	return GetDevicesOutputSerialized{
		TotalDevices: s.TotalDevices,
		Devices:      devices,
	}
}

func (s *GetDevicesOutputSerialized) Deserialize() GetDevicesOutput {
	var devices []Device
	for _, device := range s.Devices {
		deserializedDevice := device.Deserialize()
		devices = append(devices, deserializedDevice)
	}

	return GetDevicesOutput{
		TotalDevices: s.TotalDevices,
		Devices:      devices,
	}
}

// ---------------------------------------------------------------------

type GetDeviceByIdOutputSerialized struct {
	DeviceSerialized
}

func (s *GetDeviceByIdOutput) Serialize() GetDeviceByIdOutputSerialized {
	return GetDeviceByIdOutputSerialized{
		DeviceSerialized: s.Device.Serialize(),
	}
}

func (s *GetDeviceByIdOutputSerialized) Deserialize() GetDeviceByIdOutput {
	return GetDeviceByIdOutput{
		Device: s.DeviceSerialized.Deserialize(),
	}
}

// ---------------------------------------------------------------------

type DecommisionDeviceOutputSerialized struct {
	DeviceSerialized
}

func (s *DecommisionDeviceOutput) Serialize() DecommisionDeviceOutputSerialized {
	return DecommisionDeviceOutputSerialized{
		DeviceSerialized: s.Device.Serialize(),
	}
}

func (s *DecommisionDeviceOutputSerialized) Deserialize() DecommisionDeviceOutput {
	return DecommisionDeviceOutput{
		Device: s.DeviceSerialized.Deserialize(),
	}
}

// ---------------------------------------------------------------------

type RevokeActiveCertificateOutputSerialized struct {
	SlotSerialized
}

func (s *RevokeActiveCertificateOutput) Serialize() RevokeActiveCertificateOutputSerialized {
	return RevokeActiveCertificateOutputSerialized{
		SlotSerialized: s.Slot.Serialize(),
	}
}

func (s *RevokeActiveCertificateOutputSerialized) Deserialize() RevokeActiveCertificateOutput {
	return RevokeActiveCertificateOutput{
		Slot: s.SlotSerialized.Deserialize(),
	}
}

// ---------------------------------------------------------------------

type GetDeviceLogsOutputSerialized struct {
	TotalLogs int                   `json:"total_logs"`
	Logs      []DeviceLogSerialized `json:"logs"`
}

func (s *GetDeviceLogsOutput) Serialize() GetDeviceLogsOutputSerialized {
	var logs []DeviceLogSerialized
	for _, log := range s.Logs {
		logs = append(logs, log.Serialize())
	}

	return GetDeviceLogsOutputSerialized{
		TotalLogs: s.TotalLogs,
		Logs:      logs,
	}
}

func (s *GetDeviceLogsOutputSerialized) Deserialize() GetDeviceLogsOutput {
	var logs []DeviceLog
	for _, log := range s.Logs {
		logs = append(logs, log.Deserialize())
	}

	return GetDeviceLogsOutput{
		TotalLogs: s.TotalLogs,
		Logs:      logs,
	}
}
