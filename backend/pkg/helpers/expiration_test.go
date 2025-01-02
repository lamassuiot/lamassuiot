package helpers

import (
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func TestValidateValidity(t *testing.T) {
	// 0 duration
	input1 := models.Validity{
		Type:     models.Duration,
		Duration: models.TimeDuration(0),
		Time:     time.Time{},
	}

	expected1 := false
	result1 := ValidateValidity(input1)
	if result1 != expected1 {
		t.Errorf("Expected %v, but got %v", expected1, result1)
	}

	// zero time
	input2 := models.Validity{
		Type:     models.Time,
		Duration: models.TimeDuration(0),
		Time:     time.Time{},
	}

	expected2 := false
	result2 := ValidateValidity(input2)
	if result2 != expected2 {
		t.Errorf("Expected %v, but got %v", expected2, result2)
	}

	// 10 seconds duration
	duration := models.TimeDuration(time.Second * 10) // Create a models.TimeDuration variable.
	input3 := models.Validity{
		Type:     models.Duration,
		Duration: duration, // Pass a pointer to the duration variable.
		Time:     time.Time{},
	}
	expected3 := true
	result3 := ValidateValidity(input3)
	if result3 != expected3 {
		t.Errorf("Expected %v, but got %v", expected3, result3)
	}

	// now time
	input4 := models.Validity{
		Type:     models.Time,
		Duration: models.TimeDuration(0),
		Time:     time.Now(),
	}
	expected4 := true
	result4 := ValidateValidity(input4)
	if result4 != expected4 {
		t.Errorf("Expected %v, but got %v", expected4, result4)
	}
}

func TestValidateCAExpiration(t *testing.T) {
	caExp := time.Now()

	t.Run("Expiration type is Time and caExp is before expiration time", func(t *testing.T) {
		newCaExp := caExp.Add(time.Minute)
		expiration := models.Validity{
			Type: models.Time,
			Time: newCaExp,
		}
		expected := false
		result := ValidateCAExpiration(expiration, caExp)
		if result != expected {
			t.Errorf("Expected %v, but got %v", expected, result)
		}
	})

	t.Run("Expiration type is Time and caExp is after expiration time", func(t *testing.T) {
		newCaExp := caExp.Add(-time.Minute)
		expiration := models.Validity{
			Type: models.Time,
			Time: newCaExp,
		}
		expected := true
		result := ValidateCAExpiration(expiration, caExp)
		if result != expected {
			t.Errorf("Expected %v, but got %v", expected, result)
		}
	})

	t.Run("Expiration type is Duration and caExp is before expiration time", func(t *testing.T) {
		duration := models.TimeDuration(time.Minute)
		expiration := models.Validity{
			Type:     models.Duration,
			Duration: duration,
		}
		expected := false
		result := ValidateCAExpiration(expiration, caExp)
		if result != expected {
			t.Errorf("Expected %v, but got %v", expected, result)
		}
	})

	t.Run("Expiration type is Duration and caExp is after expiration time", func(t *testing.T) {
		duration := models.TimeDuration(-time.Minute)
		expiration := models.Validity{
			Type:     models.Duration,
			Duration: duration,
		}
		expected := true
		result := ValidateCAExpiration(expiration, caExp)
		if result != expected {
			t.Errorf("Expected %v, but got %v", expected, result)
		}
	})
}
