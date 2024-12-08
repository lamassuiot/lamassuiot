package config

import (
	"testing"
)

func TestPasswordMarshalText(t *testing.T) {
	p := Password("mysecretpassword")
	expected := "*************"

	marshaled, err := p.MarshalText()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if string(marshaled) != expected {
		t.Errorf("expected %s, got %s", expected, marshaled)
	}
}

func TestPasswordUnmarshalText(t *testing.T) {
	var p Password
	text := []byte("mysecretpassword")

	err := p.UnmarshalText(text)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
