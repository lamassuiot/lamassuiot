package main

import (
	"flag"
	"fmt"
	"testing"

	industrial "github.com/lamassuiot/lamassuiot/test/e2e/industrial-environment"
	cas "github.com/lamassuiot/lamassuiot/test/e2e/manage-cas"
	devices "github.com/lamassuiot/lamassuiot/test/e2e/manage-devices"
	dmss "github.com/lamassuiot/lamassuiot/test/e2e/manage-dms"
	certs "github.com/lamassuiot/lamassuiot/test/e2e/manager-certs"
)

var domain = flag.String("domain", "", "domain")
var cacert = flag.String("cert", "", "ca certificate")
var caName string
var dms_id string

func TestManageCAs(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{"ManageCAs", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			ca, err := cas.ManageCAs(1, 1, *cacert, *domain)
			if err != nil {
				t.Fail()
			} else {
				caName = ca.Name
			}
		})
	}
}
func TestIndustrialEnvironment(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{"Industrial Environment", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			dmsId, err := industrial.IndustrialEnvironment(caName, 1, 1, *cacert, *domain)
			if err != nil {
				t.Fail()
			} else {
				dms_id = dmsId
			}
		})
	}
}
func TestManageDevices(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{"ManageDevices", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			err := devices.ManageDevices(1, *cacert, *domain)
			if err != nil {
				t.Fail()
			}
		})
	}
}
func TestManageDMSs(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{"ManageDMSs", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			err := dmss.ManageDMSs(1, dms_id, caName, 1, *cacert, *domain)
			if err != nil {
				t.Fail()
			}
		})
	}
}
func TestManageCerts(t *testing.T) {
	testCases := []struct {
		name string
		err  error
	}{
		{"ManageCerts", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			err := certs.ManageCerts(caName, 1, *cacert, *domain)
			if err != nil {
				t.Fail()
			}
		})
	}
}
