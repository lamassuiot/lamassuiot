package helpers

import (
	"crypto/x509/pkix"
	"reflect"
	"testing"

	cmodels "github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
)

func TestSubjectToPkixName(t *testing.T) {

	subj1 := cmodels.Subject{}
	expected1 := pkix.Name{}
	result1 := SubjectToPkixName(subj1)
	if !reflect.DeepEqual(result1, expected1) {
		t.Errorf("Expected %v, but got %v", expected1, result1)
	}

	subj2 := cmodels.Subject{
		CommonName: "example.com",
	}
	expected2 := pkix.Name{
		CommonName: "example.com",
	}
	result2 := SubjectToPkixName(subj2)
	if !reflect.DeepEqual(result2, expected2) {
		t.Errorf("Expected %v, but got %v", expected2, result2)
	}

	subj3 := cmodels.Subject{
		Country: "US",
	}
	expected3 := pkix.Name{
		Country: []string{"US"},
	}
	result3 := SubjectToPkixName(subj3)
	if !reflect.DeepEqual(result3, expected3) {
		t.Errorf("Expected %v, but got %v", expected3, result3)
	}

	subj4 := cmodels.Subject{
		Locality: "San Francisco",
	}
	expected4 := pkix.Name{
		Locality: []string{"San Francisco"},
	}
	result4 := SubjectToPkixName(subj4)
	if !reflect.DeepEqual(result4, expected4) {
		t.Errorf("Expected %v, but got %v", expected4, result4)
	}

	subj5 := cmodels.Subject{
		Organization: "Acme Corp",
	}
	expected5 := pkix.Name{
		Organization: []string{"Acme Corp"},
	}
	result5 := SubjectToPkixName(subj5)
	if !reflect.DeepEqual(result5, expected5) {
		t.Errorf("Expected %v, but got %v", expected5, result5)
	}

	subj6 := cmodels.Subject{
		OrganizationUnit: "IT",
	}
	expected6 := pkix.Name{
		OrganizationalUnit: []string{"IT"},
	}
	result6 := SubjectToPkixName(subj6)
	if !reflect.DeepEqual(result6, expected6) {
		t.Errorf("Expected %v, but got %v", expected6, result6)
	}

	subj7 := cmodels.Subject{
		State: "California",
	}
	expected7 := pkix.Name{
		Province: []string{"California"},
	}
	result7 := SubjectToPkixName(subj7)
	if !reflect.DeepEqual(result7, expected7) {
		t.Errorf("Expected %v, but got %v", expected7, result7)
	}

	subj8 := cmodels.Subject{
		CommonName:       "example.com",
		Country:          "US",
		Locality:         "San Francisco",
		Organization:     "Acme Corp",
		OrganizationUnit: "IT",
		State:            "California",
	}
	expected8 := pkix.Name{
		CommonName:         "example.com",
		Country:            []string{"US"},
		Locality:           []string{"San Francisco"},
		Organization:       []string{"Acme Corp"},
		OrganizationalUnit: []string{"IT"},
		Province:           []string{"California"},
	}
	result8 := SubjectToPkixName(subj8)
	if !reflect.DeepEqual(result8, expected8) {
		t.Errorf("Expected %v, but got %v", expected8, result8)
	}
}

func TestPkixNameToSubject(t *testing.T) {

	pkixName1 := pkix.Name{}
	expected1 := cmodels.Subject{}
	result1 := PkixNameToSubject(pkixName1)
	if !reflect.DeepEqual(result1, expected1) {
		t.Errorf("Expected %v, but got %v", expected1, result1)
	}

	pkixName2 := pkix.Name{
		CommonName: "example.com",
	}
	expected2 := cmodels.Subject{
		CommonName: "example.com",
	}
	result2 := PkixNameToSubject(pkixName2)
	if !reflect.DeepEqual(result2, expected2) {
		t.Errorf("Expected %v, but got %v", expected2, result2)
	}

	pkixName3 := pkix.Name{
		Country: []string{"US"},
	}
	expected3 := cmodels.Subject{
		Country: "US",
	}
	result3 := PkixNameToSubject(pkixName3)
	if !reflect.DeepEqual(result3, expected3) {
		t.Errorf("Expected %v, but got %v", expected3, result3)
	}

	pkixName4 := pkix.Name{
		Organization: []string{"Acme Corp"},
	}
	expected4 := cmodels.Subject{
		Organization: "Acme Corp",
	}
	result4 := PkixNameToSubject(pkixName4)
	if !reflect.DeepEqual(result4, expected4) {
		t.Errorf("Expected %v, but got %v", expected4, result4)
	}

	pkixName5 := pkix.Name{
		OrganizationalUnit: []string{"IT"},
	}
	expected5 := cmodels.Subject{
		OrganizationUnit: "IT",
	}
	result5 := PkixNameToSubject(pkixName5)
	if !reflect.DeepEqual(result5, expected5) {
		t.Errorf("Expected %v, but got %v", expected5, result5)
	}

	pkixName6 := pkix.Name{
		Locality: []string{"San Francisco"},
	}
	expected6 := cmodels.Subject{
		Locality: "San Francisco",
	}
	result6 := PkixNameToSubject(pkixName6)
	if !reflect.DeepEqual(result6, expected6) {
		t.Errorf("Expected %v, but got %v", expected6, result6)
	}

	pkixName7 := pkix.Name{
		Province: []string{"California"},
	}
	expected7 := cmodels.Subject{
		State: "California",
	}
	result7 := PkixNameToSubject(pkixName7)
	if !reflect.DeepEqual(result7, expected7) {
		t.Errorf("Expected %v, but got %v", expected7, result7)
	}

	pkixName8 := pkix.Name{
		CommonName:         "example.com",
		Country:            []string{"US"},
		Organization:       []string{"Acme Corp"},
		OrganizationalUnit: []string{"IT"},
		Locality:           []string{"San Francisco"},
		Province:           []string{"California"},
	}
	expected8 := cmodels.Subject{
		CommonName:       "example.com",
		Country:          "US",
		Organization:     "Acme Corp",
		OrganizationUnit: "IT",
		Locality:         "San Francisco",
		State:            "California",
	}
	result8 := PkixNameToSubject(pkixName8)
	if !reflect.DeepEqual(result8, expected8) {
		t.Errorf("Expected %v, but got %v", expected8, result8)
	}
}

func TestPkixNameToString(t *testing.T) {
	subject1 := pkix.Name{}
	expected1 := "C=[]/ST=[]/L=[]/O=[]/OU=[]/CN="
	result1 := PkixNameToString(subject1)
	if result1 != expected1 {
		t.Errorf("Expected %v, but got %v", expected1, result1)
	}

	subject2 := pkix.Name{
		CommonName: "example.com",
	}
	expected2 := "C=[]/ST=[]/L=[]/O=[]/OU=[]/CN=example.com"
	result2 := PkixNameToString(subject2)
	if result2 != expected2 {
		t.Errorf("Expected %v, but got %v", expected2, result2)
	}

	subject3 := pkix.Name{
		Country: []string{"US"},
	}
	expected3 := "C=[US]/ST=[]/L=[]/O=[]/OU=[]/CN="
	result3 := PkixNameToString(subject3)
	if result3 != expected3 {
		t.Errorf("Expected %v, but got %v", expected3, result3)
	}

	subject4 := pkix.Name{
		Organization: []string{"Acme Corp"},
	}
	expected4 := "C=[]/ST=[]/L=[]/O=[Acme Corp]/OU=[]/CN="
	result4 := PkixNameToString(subject4)
	if result4 != expected4 {
		t.Errorf("Expected %v, but got %v", expected4, result4)
	}

	subject5 := pkix.Name{
		OrganizationalUnit: []string{"IT"},
	}
	expected5 := "C=[]/ST=[]/L=[]/O=[]/OU=[IT]/CN="
	result5 := PkixNameToString(subject5)
	if result5 != expected5 {
		t.Errorf("Expected %v, but got %v", expected5, result5)
	}

	subject6 := pkix.Name{
		Locality: []string{"San Francisco"},
	}
	expected6 := "C=[]/ST=[]/L=[San Francisco]/O=[]/OU=[]/CN="
	result6 := PkixNameToString(subject6)
	if result6 != expected6 {
		t.Errorf("Expected %v, but got %v", expected6, result6)
	}

	subject7 := pkix.Name{
		Province: []string{"California"},
	}
	expected7 := "C=[]/ST=[California]/L=[]/O=[]/OU=[]/CN="
	result7 := PkixNameToString(subject7)
	if result7 != expected7 {
		t.Errorf("Expected %v, but got %v", expected7, result7)
	}

	subject8 := pkix.Name{
		CommonName:         "example.com",
		Country:            []string{"US"},
		Organization:       []string{"Acme Corp"},
		OrganizationalUnit: []string{"IT"},
		Locality:           []string{"San Francisco"},
		Province:           []string{"California"},
	}
	expected8 := "C=[US]/ST=[California]/L=[San Francisco]/O=[Acme Corp]/OU=[IT]/CN=example.com"
	result8 := PkixNameToString(subject8)
	if result8 != expected8 {
		t.Errorf("Expected %v, but got %v", expected8, result8)
	}
}
