package helpers

import (
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
)

func TestValidateExpirationTimeRef(t *testing.T) {

	input1 := models.Expiration{
		Type:     models.Duration,
		Duration: nil,
		Time:     nil,
	}
	expected1 := false
	result1 := ValidateExpirationTimeRef(input1)
	if result1 != expected1 {
		t.Errorf("Expected %v, but got %v", expected1, result1)
	}

	input2 := models.Expiration{
		Type:     models.Time,
		Duration: nil,
		Time:     nil,
	}
	expected2 := false
	result2 := ValidateExpirationTimeRef(input2)
	if result2 != expected2 {
		t.Errorf("Expected %v, but got %v", expected2, result2)
	}

	duration := models.TimeDuration(0) // Create a models.TimeDuration variable.
	input3 := models.Expiration{
		Type:     models.Duration,
		Duration: &duration, // Pass a pointer to the duration variable.
		Time:     nil,
	}
	expected3 := true
	result3 := ValidateExpirationTimeRef(input3)
	if result3 != expected3 {
		t.Errorf("Expected %v, but got %v", expected3, result3)
	}

	input4 := models.Expiration{
		Type:     models.Time,
		Duration: nil,
		Time:     &time.Time{},
	}
	expected4 := true
	result4 := ValidateExpirationTimeRef(input4)
	if result4 != expected4 {
		t.Errorf("Expected %v, but got %v", expected4, result4)
	}
}

func TestValidateCAExpiration(t *testing.T) {
	caExp := time.Now()

	t.Run("Expiration type is Time and caExp is before expiration time", func(t *testing.T) {
		newCaExp := caExp.Add(time.Minute)
		expiration := models.Expiration{
			Type: models.Time,
			Time: &newCaExp,
		}
		expected := false
		result := ValidateCAExpiration(expiration, caExp)
		if result != expected {
			t.Errorf("Expected %v, but got %v", expected, result)
		}
	})

	t.Run("Expiration type is Time and caExp is after expiration time", func(t *testing.T) {
		newCaExp := caExp.Add(-time.Minute)
		expiration := models.Expiration{
			Type: models.Time,
			Time: &newCaExp,
		}
		expected := true
		result := ValidateCAExpiration(expiration, caExp)
		if result != expected {
			t.Errorf("Expected %v, but got %v", expected, result)
		}
	})

	t.Run("Expiration type is Duration and caExp is before expiration time", func(t *testing.T) {
		duration := models.TimeDuration(time.Minute)
		expiration := models.Expiration{
			Type:     models.Duration,
			Duration: &duration,
		}
		expected := false
		result := ValidateCAExpiration(expiration, caExp)
		if result != expected {
			t.Errorf("Expected %v, but got %v", expected, result)
		}
	})

	t.Run("Expiration type is Duration and caExp is after expiration time", func(t *testing.T) {
		duration := models.TimeDuration(-time.Minute)
		expiration := models.Expiration{
			Type:     models.Duration,
			Duration: &duration,
		}
		expected := true
		result := ValidateCAExpiration(expiration, caExp)
		if result != expected {
			t.Errorf("Expected %v, but got %v", expected, result)
		}
	})
}
