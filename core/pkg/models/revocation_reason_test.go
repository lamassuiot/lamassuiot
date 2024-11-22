package models

import (
	"fmt"
	"testing"
)

func TestRevocationReasonMarshalText(t *testing.T) {
	reason := RevocationReason(1)
	expected := []byte("KeyCompromise")

	data, err := reason.MarshalText()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if string(data) != string(expected) {
		t.Fatalf("unexpected data: got %s, want %s", data, expected)
	}
}

func TestRevocationReasonMarshalTextUnsupportedCode(t *testing.T) {
	reason := RevocationReason(7)

	_, err := reason.MarshalText()
	if err == nil {
		t.Fatal("expected error, but got nil")
	}

	expectedErr := fmt.Errorf("unsupported revocation code")
	if err.Error() != expectedErr.Error() {
		t.Fatalf("unexpected error: got %s, want %s", err, expectedErr)
	}
}

func TestRevocationReasonUnmarshalText(t *testing.T) {
	text := []byte("Superseded")
	expected := RevocationReason(4)

	var reason RevocationReason
	err := reason.UnmarshalText(text)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if reason != expected {
		t.Fatalf("unexpected data: got %v, want %v", reason, expected)
	}
}

func TestRevocationReasonUnmarshalTextUnsupportedCode(t *testing.T) {
	text := []byte("InvalidCode")

	var reason RevocationReason
	err := reason.UnmarshalText(text)
	if err == nil {
		t.Fatal("expected error, but got nil")
	}

	expectedErr := fmt.Errorf("unsupported revocation code")
	if err.Error() != expectedErr.Error() {
		t.Fatalf("unexpected error: got %s, want %s", err, expectedErr)
	}
}

func TestRevocationReasonString(t *testing.T) {
	reason := RevocationReason(3)
	expected := "AffiliationChanged"

	result := reason.String()
	if result != expected {
		t.Fatalf("unexpected data: got %s, want %s", result, expected)
	}
}

func TestRevocationReasonMarshalJSON(t *testing.T) {
	reason := RevocationReason(6)
	expected := []byte("\"CertificateHold\"")

	data, err := reason.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if string(data) != string(expected) {
		t.Fatalf("unexpected data: got %s, want %s", data, expected)
	}
}

func TestRevocationReasonUnmarshalJSON(t *testing.T) {
	data := []byte("\"Unspecified\"")
	expected := RevocationReason(0)

	var reason RevocationReason
	err := reason.UnmarshalJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if reason != expected {
		t.Fatalf("unexpected data: got %v, want %v", reason, expected)
	}
}

func TestRevocationReasonUnmarshalJSONInvalidData(t *testing.T) {
	data := []byte("InvalidData")

	var reason RevocationReason
	err := reason.UnmarshalJSON(data)
	if err == nil {
		t.Fatal("expected error, but got nil")
	}

	expectedErr := fmt.Errorf("unsupported revocation code")
	if err.Error() != expectedErr.Error() {
		t.Fatalf("unexpected error: got %s, want %s", err, expectedErr)
	}
}
