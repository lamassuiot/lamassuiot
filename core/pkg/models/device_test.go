package models

import "testing"

func TestDeviceEventRecordTableName(t *testing.T) {
	if got, want := (DeviceEventRecord{}).TableName(), "device_events"; got != want {
		t.Fatalf("DeviceEventRecord.TableName() = %q, want %q", got, want)
	}
}
