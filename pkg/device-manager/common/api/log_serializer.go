package api

import (
	"encoding/base64"
	"encoding/pem"

	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
)

type SubjectLogSerialized struct {
	CommonName string `json:"common_name"`
}

func (s *Subject) ToSerializedLog() SubjectLogSerialized {
	return SubjectLogSerialized{
		CommonName: s.CommonName,
	}
}

type DeviceLogSerialized struct {
	ID     string       `json:"id"`
	Alias  string       `json:"alias"`
	Status DeviceStatus `json:"status"`
}

func (s *Device) ToSerializedLog() DeviceLogSerialized {

	return DeviceLogSerialized{
		ID:     s.ID,
		Alias:  s.Alias,
		Status: s.Status,
	}
}

type DevicesManagerStatsLogSerialized struct {
	DevicesStats map[DeviceStatus]int            `json:"devices_stats"`
	SlotsStats   map[caApi.CertificateStatus]int `json:"slots_stats"`
}

func (s *DevicesManagerStats) ToSerializedLog() DevicesManagerStatsLogSerialized {
	return DevicesManagerStatsLogSerialized{
		DevicesStats: s.DevicesStats,
		SlotsStats:   s.SlotsStats,
	}
}

type CertificateLogSerialized struct {
	CAName              string                        `json:"ca_name"`
	SerialNumber        string                        `json:"serial_number"`
	Certificate         string                        `json:"certificate"`
	Status              caApi.CertificateStatus       `json:"status"`
	KeyMetadata         KeyStrengthMetadataSerialized `json:"key_metadata"`
	Subject             SubjectLogSerialized          `json:"subject"`
	ValidFrom           int                           `json:"valid_from"`
	ValidTo             int                           `json:"valid_to"`
	RevocationTimestamp int                           `json:"revocation_timestamp,omitempty"`
	RevocationReason    string                        `json:"revocation_reason,omitempty"`
}

func (s *Certificate) ToSerializedLog() CertificateLogSerialized {
	var certificateString string = ""
	if s.Certificate != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate.Raw})
		certEnc := make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(certEnc, pemCert)
		//certificateString = string(certEnc)
	}

	serializer := CertificateLogSerialized{
		CAName:           s.CAName,
		SerialNumber:     s.SerialNumber,
		Certificate:      certificateString,
		Status:           s.Status,
		KeyMetadata:      s.KeyMetadata.Serialize(),
		Subject:          s.Subject.ToSerializedLog(),
		ValidFrom:        int(s.ValidFrom.UnixMilli()),
		ValidTo:          int(s.ValidTo.UnixMilli()),
		RevocationReason: s.RevocationReason,
	}

	return serializer
}

type SlotLogSerialized struct {
	ID                  string                   `json:"id"`
	ActiveCertificate   CertificateLogSerialized `json:"active_certificate"`
	ArchiveCertificates []CertificateSerialized  `json:"archive_certificates"`
}

func (s *Slot) ToSerializedLog() SlotLogSerialized {
	var archiveCertificates []CertificateSerialized
	for _, cert := range s.ArchiveCertificates {
		archiveCertificates = append(archiveCertificates, cert.Serialize())
	}
	return SlotLogSerialized{
		ID:                s.ID,
		ActiveCertificate: s.ActiveCertificate.ToSerializedLog(),
		//ArchiveCertificates: archiveCertificates,
	}
}

type DeviceLogsSerializedLog struct {
	DevciceID string          `json:"device_id"`
	Logs      []LogSerialized `json:"logs"`
}

func (s *DeviceLogs) ToSerializedLog() DeviceLogsSerializedLog {
	logs := []LogSerialized{}
	for _, log := range s.Logs {
		logs = append(logs, log.Serialize())
	}
	slotLogsMap := map[string][]LogSerialized{}
	for slotID, slotLog := range s.SlotLogs {
		slotLogs := []LogSerialized{}
		for _, log := range slotLog {
			slotLogs = append(slotLogs, log.Serialize())
		}
		slotLogsMap[slotID] = slotLogs
	}
	return DeviceLogsSerializedLog{
		DevciceID: s.DevciceID,
		Logs:      logs,
	}
}

// ---------------------------------------------------------------------

type GetStatsOutputLogSerialized struct {
	DevicesManagerStatsSerialized DevicesManagerStatsLogSerialized `json:"stats"`
}

func (s *GetStatsOutput) ToSerializedLog() GetStatsOutputLogSerialized {
	return GetStatsOutputLogSerialized{
		DevicesManagerStatsSerialized: s.DevicesManagerStats.ToSerializedLog(),
	}
}

// ---------------------------------------------------------------------

type CreateDeviceOutputLogSerialized struct {
	DeviceLogSerialized
}

func (s *CreateDeviceOutput) ToSerializedLog() CreateDeviceOutputLogSerialized {
	return CreateDeviceOutputLogSerialized{
		DeviceLogSerialized: s.Device.ToSerializedLog(),
	}
}

// ---------------------------------------------------------------------

type UpdateDeviceMetadataOutputLogSerialized struct {
	DeviceLogSerialized
}

func (s *UpdateDeviceMetadataOutput) ToSerializedLog() UpdateDeviceMetadataOutputLogSerialized {
	return UpdateDeviceMetadataOutputLogSerialized{
		DeviceLogSerialized: s.Device.ToSerializedLog(),
	}
}

// ---------------------------------------------------------------------

type GetDevicesOutputLogSerialized struct {
	TotalDevices int `json:"total_devices"`
}

func (s *GetDevicesOutput) ToSerializedLog() GetDevicesOutputLogSerialized {

	return GetDevicesOutputLogSerialized{
		TotalDevices: s.TotalDevices,
	}
}

type GetDevicesByDMSOutputLogSerialized struct {
	TotalDevices int `json:"total_devices"`
}

func (s *GetDevicesByDMSOutput) ToSerializedLog() GetDevicesByDMSOutputLogSerialized {

	return GetDevicesByDMSOutputLogSerialized{
		TotalDevices: s.TotalDevices,
	}
}

// ---------------------------------------------------------------------

type GetDeviceByIdOutputLogSerialized struct {
	DeviceLogSerialized
}

func (s *GetDeviceByIdOutput) ToSerializedLog() GetDeviceByIdOutputLogSerialized {
	return GetDeviceByIdOutputLogSerialized{
		DeviceLogSerialized: s.Device.ToSerializedLog(),
	}
}

// ---------------------------------------------------------------------

type DecommisionDeviceOutputLogSerialized struct {
	DeviceLogSerialized
}

func (s *DecommisionDeviceOutput) ToSerializedLog() DecommisionDeviceOutputLogSerialized {
	return DecommisionDeviceOutputLogSerialized{
		DeviceLogSerialized: s.Device.ToSerializedLog(),
	}
}

// ---------------------------------------------------------------------

type RevokeActiveCertificateOutputLogSerialized struct {
	SlotLogSerialized
}

func (s *RevokeActiveCertificateOutput) ToSerializedLog() RevokeActiveCertificateOutputLogSerialized {
	return RevokeActiveCertificateOutputLogSerialized{
		SlotLogSerialized: s.Slot.ToSerializedLog(),
	}
}

// ---------------------------------------------------------------------

type GetDeviceLogsOutputLogSerialized struct {
	DeviceLogsSerializedLog
}

func (s *GetDeviceLogsOutput) ToSerializedLog() GetDeviceLogsOutputLogSerialized {
	return GetDeviceLogsOutputLogSerialized{
		DeviceLogsSerializedLog: s.DeviceLogs.ToSerializedLog(),
	}
}

// ---------------------------------------------------------------------

type ForceReenrollOtputLogSerialized struct {
	DeviceID          string `json:"device_id"`
	SlotID            string `json:"slot_id"`
	ForceReenrollment bool   `json:"force_reenrollment"`
}

func (s *ForceReenrollOtput) ToSerializedLog() ForceReenrollOtputLogSerialized {
	return ForceReenrollOtputLogSerialized{
		DeviceID:          s.DeviceID,
		SlotID:            s.SlotID,
		ForceReenrollment: s.ForceReenroll,
	}
}
