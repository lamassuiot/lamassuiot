package helpers

import (
	"math/big"
	"testing"
)

func TestInsertNth(t *testing.T) {
	// Caso de prueba 1: cadena vacía
	s1 := ""
	n1 := 2
	sep1 := '-'
	expected1 := ""
	result1 := insertNth(s1, n1, sep1)
	if result1 != expected1 {
		t.Errorf("Expected %v, but got %v", expected1, result1)
	}

	// Caso de prueba 2: cadena con longitud impar
	s2 := "123"
	n2 := 2
	sep2 := '-'
	expected2 := "01-23"
	result2 := insertNth(s2, n2, sep2)
	if result2 != expected2 {
		t.Errorf("Expected %v, but got %v", expected2, result2)
	}

	// Caso de prueba 3: cadena con longitud par
	s3 := "1234"
	n3 := 2
	sep3 := '-'
	expected3 := "12-34"
	result3 := insertNth(s3, n3, sep3)
	if result3 != expected3 {
		t.Errorf("Expected %v, but got %v", expected3, result3)
	}
}

func TestToHexInt(t *testing.T) {
	// Caso de prueba 1: número cero
	n1 := big.NewInt(0)
	expected1 := "0"
	result1 := toHexInt(n1)
	if result1 != expected1 {
		t.Errorf("Expected %v, but got %v", expected1, result1)
	}

	// Caso de prueba 2: número positivo
	n2 := big.NewInt(255)
	expected2 := "ff"
	result2 := toHexInt(n2)
	if result2 != expected2 {
		t.Errorf("Expected %v, but got %v", expected2, result2)
	}

	// Caso de prueba 3: número negativo
	n3 := big.NewInt(-255)
	expected3 := "-ff"
	result3 := toHexInt(n3)
	if result3 != expected3 {
		t.Errorf("Expected %v, but got %v", expected3, result3)
	}
}

func TestSerialNumberToString(t *testing.T) {
	// Caso de prueba 1: número cero
	n1 := big.NewInt(0)
	expected1 := "00"
	result1 := SerialNumberToString(n1)
	if result1 != expected1 {
		t.Errorf("Expected %v, but got %v", expected1, result1)
	}

	// Caso de prueba 2: número positivo
	n2 := big.NewInt(255)
	expected2 := "ff"
	result2 := SerialNumberToString(n2)
	if result2 != expected2 {
		t.Errorf("Expected %v, but got %v", expected2, result2)
	}

	// Caso de prueba 3: número negativo
	n3 := big.NewInt(-255)
	expected3 := "ff"
	result3 := SerialNumberToString(n3)
	if result3 != expected3 {
		t.Errorf("Expected %v, but got %v", expected3, result3)
	}

	// Caso de prueba 4: > 255, longitud impar
	n4 := big.NewInt(256)
	expected4 := "01-00"
	result4 := SerialNumberToString(n4)
	if result4 != expected4 {
		t.Errorf("Expected %v, but got %v", expected4, result4)
	}

	// Caso de prueba 5: > 255, longitud par
	n5 := big.NewInt(1024 * 4)
	expected5 := "10-00"
	result5 := SerialNumberToString(n5)
	if result5 != expected5 {
		t.Errorf("Expected %v, but got %v", expected5, result5)
	}

	// Caso de prueba 6: long number
	n6 := new(big.Int).Exp(big.NewInt(2), big.NewInt(1024), nil)
	expected6 := "01-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00"
	result6 := SerialNumberToString(n6)
	if result6 != expected6 {
		t.Errorf("Expected %v, but got %v", expected6, result6)
	}
}
