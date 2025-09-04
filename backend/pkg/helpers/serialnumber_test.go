package helpers

import (
	"math/big"
	"testing"
)

func TestSerialNumberToString(t *testing.T) {
	// Caso de prueba 1: número cero
	n1 := big.NewInt(0)
	expected1 := "00"
	result1 := SerialNumberToHexString(n1)
	if result1 != expected1 {
		t.Errorf("Expected %v, but got %v", expected1, result1)
	}

	// Caso de prueba 2: número positivo
	n2 := big.NewInt(255)
	expected2 := "ff"
	result2 := SerialNumberToHexString(n2)
	if result2 != expected2 {
		t.Errorf("Expected %v, but got %v", expected2, result2)
	}

	// Caso de prueba 3: número negativo
	n3 := big.NewInt(-255)
	expected3 := "ff"
	result3 := SerialNumberToHexString(n3)
	if result3 != expected3 {
		t.Errorf("Expected %v, but got %v", expected3, result3)
	}

	// Caso de prueba 4: > 255, longitud impar
	n4 := big.NewInt(256)
	expected4 := "0100"
	result4 := SerialNumberToHexString(n4)
	if result4 != expected4 {
		t.Errorf("Expected %v, but got %v", expected4, result4)
	}

	// Caso de prueba 5: > 255, longitud par
	n5 := big.NewInt(1024 * 4)
	expected5 := "1000"
	result5 := SerialNumberToHexString(n5)
	if result5 != expected5 {
		t.Errorf("Expected %v, but got %v", expected5, result5)
	}

	// Caso de prueba 6: long number
	n6 := new(big.Int).Exp(big.NewInt(2), big.NewInt(1024), nil)
	expected6 := "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	result6 := SerialNumberToHexString(n6)
	if result6 != expected6 {
		t.Errorf("Expected %v, but got %v", expected6, result6)
	}
}
