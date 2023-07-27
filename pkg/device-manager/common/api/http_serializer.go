package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"

	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lib/pq"
)

type DevicesManagerStatsSerialized struct {
	DevicesStats map[DeviceStatus]int            `json:"devices_stats"`
	SlotsStats   map[caApi.CertificateStatus]int `json:"slots_stats"`
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
	KeyType     KeyType     `json:"type"`
	KeyBits     int         `json:"bits"`
	KeyStrength KeyStrength `json:"strength"`
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
	Status              caApi.CertificateStatus       `json:"status"`
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
		ValidFrom:        int(s.ValidFrom.UnixMilli()),
		ValidTo:          int(s.ValidTo.UnixMilli()),
		RevocationReason: s.RevocationReason,
	}

	if s.RevocationTimestamp.Valid {
		serializer.RevocationTimestamp = int(s.RevocationTimestamp.Time.UnixMilli())
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
		Status:       s.Status,
		SerialNumber: s.SerialNumber,
		ValidFrom:    time.UnixMilli(int64(s.ValidFrom)),
		ValidTo:      time.UnixMilli(int64(s.ValidTo)),
		KeyMetadata:  s.KeyMetadata.Deserialize(),
		Subject:      s.Subject.Deserialize(),
		Certificate:  certificate,
	}

	if s.RevocationTimestamp > 0 {
		serializer.RevocationTimestamp = pq.NullTime{
			Time:  time.UnixMilli(int64(s.RevocationTimestamp)),
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
	archiveCertificates := make([]CertificateSerialized, 0)
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
	archiveCertificates := make([]*Certificate, 0)
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
	ID                 string           `json:"id"`
	Alias              string           `json:"alias"`
	DmsName            string           `json:"dms_name"`
	Status             DeviceStatus     `json:"status"`
	Slots              []SlotSerialized `json:"slots"`
	AllowNewEnrollment bool             `json:"allow_new_enrollment"`
	Description        string           `json:"description"`
	Tags               []string         `json:"tags"`
	IconName           string           `json:"icon_name"`
	IconColor          string           `json:"icon_color"`
	CreationTimestamp  int              `json:"creation_timestamp"`
}

func (s *Device) Serialize() DeviceSerialized {
	slots := []SlotSerialized{}
	for _, slot := range s.Slots {
		serializedSlot := slot.Serialize()
		slots = append(slots, serializedSlot)
	}
	return DeviceSerialized{
		ID:                 s.ID,
		DmsName:            s.DmsName,
		Alias:              s.Alias,
		Status:             s.Status,
		AllowNewEnrollment: s.AllowNewEnrollment,
		Slots:              slots,
		Description:        s.Description,
		Tags:               s.Tags,
		IconName:           s.IconName,
		IconColor:          s.IconColor,
		CreationTimestamp:  int(s.CreationTimestamp.UnixMilli()),
	}
}

func (s *DeviceSerialized) Deserialize() Device {
	slots := []*Slot{}
	for _, slot := range s.Slots {
		deserializedSlot := slot.Deserialize()
		slots = append(slots, &deserializedSlot)
	}

	return Device{
		ID:                 s.ID,
		DmsName:            s.DmsName,
		Alias:              s.Alias,
		Status:             s.Status,
		AllowNewEnrollment: s.AllowNewEnrollment,
		Slots:              slots,
		Description:        s.Description,
		Tags:               s.Tags,
		IconName:           s.IconName,
		IconColor:          s.IconColor,
		CreationTimestamp:  time.UnixMilli(int64(s.CreationTimestamp)),
	}
}

type LogSerialized struct {
	LogType        string `json:"log_type"`
	LogMessage     string `json:"log_message"`
	LogDescription string `json:"log_description"`
	Timestamp      int    `json:"timestamp"`
}

func (s *Log) Serialize() LogSerialized {
	return LogSerialized{
		LogType:        string(s.LogType),
		LogMessage:     s.LogMessage,
		LogDescription: s.LogDescription,
		Timestamp:      int(s.Timestamp.UnixMilli()),
	}
}

func (s *LogSerialized) Deserialize() Log {
	return Log{
		LogType:        LogType(s.LogType),
		LogMessage:     s.LogMessage,
		LogDescription: s.LogDescription,
		Timestamp:      time.UnixMilli(int64(s.Timestamp)),
	}
}

type DeviceLogsSerialized struct {
	DevciceID string                     `json:"device_id"`
	Logs      []LogSerialized            `json:"logs"`
	SlotLogs  map[string][]LogSerialized `json:"slot_logs"`
}

func (s *DeviceLogs) Serialize() DeviceLogsSerialized {
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
	return DeviceLogsSerialized{
		DevciceID: s.DevciceID,
		Logs:      logs,
		SlotLogs:  slotLogsMap,
	}
}

func (s *DeviceLogsSerialized) Deserialize() DeviceLogs {
	logs := []Log{}
	for _, log := range s.Logs {
		logs = append(logs, log.Deserialize())
	}
	slotLogsMap := map[string][]Log{}
	for slotID, slotLog := range s.SlotLogs {
		slotLogs := []Log{}
		for _, log := range slotLog {
			slotLogs = append(slotLogs, log.Deserialize())
		}
		slotLogsMap[slotID] = slotLogs
	}
	return DeviceLogs{
		DevciceID: s.DevciceID,
		Logs:      logs,
		SlotLogs:  slotLogsMap,
	}
}

// ---------------------------------------------------------------------

type GetStatsOutputSerialized struct {
	DevicesManagerStatsSerialized DevicesManagerStatsSerialized `json:"stats"`
	ScanDate                      int                           `json:"scan_date"`
}

func (s *GetStatsOutput) Serialize() GetStatsOutputSerialized {
	return GetStatsOutputSerialized{
		DevicesManagerStatsSerialized: s.DevicesManagerStats.Serialize(),
		ScanDate:                      int(s.ScanDate.UnixMilli()),
	}
}

func (s *GetStatsOutputSerialized) Deserialize() GetStatsOutput {
	return GetStatsOutput{
		DevicesManagerStats: s.DevicesManagerStatsSerialized.Deserialize(),
		ScanDate:            time.UnixMilli(int64(s.ScanDate)),
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
	TotalDevices int                `json:"total_devices"`
	Devices      []DeviceSerialized `json:"devices"`
}

func (s *GetDevicesOutput) Serialize() GetDevicesOutputSerialized {
	devices := []DeviceSerialized{}
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

type GetDevicesByDMSOutputSerialized struct {
	TotalDevices int                `json:"total_devices"`
	Devices      []DeviceSerialized `json:"devices"`
}

func (s *GetDevicesByDMSOutput) Serialize() GetDevicesByDMSOutputSerialized {
	devices := []DeviceSerialized{}
	for _, device := range s.Devices {
		devices = append(devices, device.Serialize())
	}

	return GetDevicesByDMSOutputSerialized{
		TotalDevices: s.TotalDevices,
		Devices:      devices,
	}
}

func (s *GetDevicesByDMSOutputSerialized) Deserialize() GetDevicesByDMSOutput {
	var devices []Device
	for _, device := range s.Devices {
		deserializedDevice := device.Deserialize()
		devices = append(devices, deserializedDevice)
	}

	return GetDevicesByDMSOutput{
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
	DeviceLogsSerialized
}

func (s *GetDeviceLogsOutput) Serialize() GetDeviceLogsOutputSerialized {
	return GetDeviceLogsOutputSerialized{
		DeviceLogsSerialized: s.DeviceLogs.Serialize(),
	}
}

func (s *GetDeviceLogsOutputSerialized) Deserialize() GetDeviceLogsOutput {
	return GetDeviceLogsOutput{
		DeviceLogs: s.DeviceLogsSerialized.Deserialize(),
	}
}

// ---------------------------------------------------------------------

type ForceReenrollSerialized struct {
	DeviceID      string `json:"device_id"`
	SlotID        string `json:"slot_id"`
	ForceReenroll bool   `json:"require_reenrollment"`
	Certificate   string `json:"crt"`
}
type ForceReenrollOutputSerialized struct {
	ForceReenrollSerialized
}

func (s *ForceReenrollOtput) Serialize() ForceReenrollSerialized {
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Crt.Raw})
	encodedCrt := base64.StdEncoding.EncodeToString(crt)
	return ForceReenrollSerialized{
		DeviceID:      s.DeviceID,
		SlotID:        s.SlotID,
		ForceReenroll: s.ForceReenroll,
		Certificate:   encodedCrt,
	}
}

func (s *ForceReenrollSerialized) Deserialize() ForceReenrollOtput {
	crt, _ := base64.StdEncoding.DecodeString(s.Certificate)
	block, _ := pem.Decode(crt)
	certificate, _ := x509.ParseCertificate(block.Bytes)

	return ForceReenrollOtput{
		DeviceID:      s.DeviceID,
		SlotID:        s.SlotID,
		ForceReenroll: s.ForceReenroll,
		Crt:           certificate,
	}
}

// ---------------------------------------------------------------------
