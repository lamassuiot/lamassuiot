package device

import "errors"

type PrivateKeyMetadata struct {
	KeyType string `json:"type"`
	KeyBits int    `json:"bits"`
}

type IconType struct {
	IconName  string `json:"icon_name"`
	IconColor string `json:"icon_color"`
}

type DeviceStatus string

const (
	DevicePendingProvision DeviceStatus = "PENDING_PROVISION"
	DeviceProvisioned      DeviceStatus = "DEVICE_PROVISIONED"
	DeviceCertRevoked      DeviceStatus = "CERT_REVOKED"
	DeviceCertExpired      DeviceStatus = "CERT_EXPIRED"
	DeviceDecommisioned    DeviceStatus = "DEVICE_DECOMMISIONED"
)

func Type(s string) (DeviceStatus, error) {
	switch s {
	case "PENDING_PROVISION":
		return DevicePendingProvision, nil
	case "DEVICE_PROVISIONED":
		return DeviceProvisioned, nil
	case "CERT_REVOKED":
		return DeviceCertRevoked, nil
	case "CERT_EXPIRED":
		return DeviceCertExpired, nil
	case "DEVICE_DECOMMISIONED":
		return DeviceDecommisioned, nil
	}
	return "DEVICE_DECOMMISIONED", errors.New("DeviceStatus parsing error")
}

func (c DeviceStatus) String() string {
	switch c {
	case DevicePendingProvision:
		return "PENDING_PROVISION"
	case DeviceProvisioned:
		return "DEVICE_PROVISIONED"
	case DeviceCertRevoked:
		return "CERT_REVOKED"
	case DeviceCertExpired:
		return "CERT_EXPIRED"
	case DeviceDecommisioned:
		return "DEVICE_DECOMMISIONED"
	}
	return "PENDING_PROVISION"
}

type LogDeviceStatus string

const (
	LogDeviceCreated        LogDeviceStatus = "LOG_DEVICE_CREATED"
	LogPendingProvision     LogDeviceStatus = "LOG_PENDING_PROVISION"
	LogProvisioned          LogDeviceStatus = "LOG_PROVISIONED"
	LogCertRevoked          LogDeviceStatus = "LOG_CERT_REVOKED"
	LogCertExpired          LogDeviceStatus = "LOG_CERT_EXPIRED"
	LogDeviceDecommisioned  LogDeviceStatus = "LOG_DEVICE_DECOMMISIONED"
	LogDeviceReenroll       LogDeviceStatus = "LOG_DEVICE_REENROLL"
	LogDeviceCertExpiration LogDeviceStatus = "LOG_DEVICE_CERT_EXPIRATION"
)

func LogDeviceStatusType(s string) (LogDeviceStatus, error) {
	switch s {
	case "LOG_DEVICE_CREATED":
		return LogDeviceCreated, nil
	case "LOG_PENDING_PROVISION":
		return LogPendingProvision, nil
	case "LOG_PROVISIONED":
		return LogProvisioned, nil
	case "LOG_CERT_REVOKED":
		return LogCertRevoked, nil
	case "LOG_CERT_EXPIRED":
		return LogCertExpired, nil
	case "LOG_DEVICE_DECOMMISIONED":
		return LogDeviceDecommisioned, nil
	case "LOG_DEVICE_REENROLL":
		return LogDeviceReenroll, nil
	case "LOG_DEVICE_CERT_EXPIRATION":
		return LogDeviceCertExpiration, nil
	}
	return "LOG_DEVICE_DECOMMISIONED", errors.New("LogDeviceStatus parsing error")
}

func (c LogDeviceStatus) String() string {
	switch c {
	case LogDeviceCreated:
		return "LOG_DEVICE_CREATED"
	case LogPendingProvision:
		return "LOG_PENDING_PROVISION"
	case LogProvisioned:
		return "LOG_PROVISIONED"
	case LogCertRevoked:
		return "LOG_CERT_REVOKED"
	case LogCertExpired:
		return "LOG_DEVICE_DECOMMISIONED"
	case LogDeviceDecommisioned:
		return "LOG_DEVICE_DECOMMISIONED"
	case LogDeviceReenroll:
		return "LOG_DEVICE_REENROLL"
	case LogDeviceCertExpiration:
		return "LOG_DEVICE_CERT_EXPIRATION"
	}
	return "LOG_DEVICE_DECOMMISIONED"
}

type CertHistoryStatus string

const (
	CertHistoryActive  CertHistoryStatus = "ACTIVE"
	CertHistoryExpired CertHistoryStatus = "EXPIRED"
	CertHistoryRevoked CertHistoryStatus = "REVOKED"
)

func CertHistoryStatusType(s string) (CertHistoryStatus, error) {
	switch s {
	case "ACTIVE":
		return CertHistoryActive, nil
	case "EXPIRED":
		return CertHistoryExpired, nil
	case "REVOKED":
		return CertHistoryRevoked, nil
	}
	return "REVOKED", errors.New("DeviceStatus parsing error")
}

func (c CertHistoryStatus) String() string {
	switch c {
	case CertHistoryActive:
		return "ACTIVE"
	case CertHistoryExpired:
		return "EXPIRED"
	case CertHistoryRevoked:
		return "REVOKED"
	}
	return "REVOKED"
}
