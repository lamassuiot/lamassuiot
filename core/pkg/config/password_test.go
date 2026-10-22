package config

import (
	"encoding/json"
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

	if p != Password("mysecretpassword") {
		t.Errorf("expected mysecretpassword, got %s", p)
	}
}

func TestPasswordJSONRoundTrip(t *testing.T) {
	type wrapper struct {
		Secret Password `json:"secret"`
	}

	b, err := json.Marshal(wrapper{Secret: "mysecretpassword"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var decoded wrapper
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if decoded.Secret != Password("mysecretpassword") {
		t.Errorf("expected mysecretpassword, got %s (encoded as %s)", decoded.Secret, b)
	}
}
