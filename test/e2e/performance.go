package main

import (
	"flag"
	"fmt"
	"strconv"

	industrial "github.com/lamassuiot/lamassuiot/test/e2e/industrial-environment"
	cas "github.com/lamassuiot/lamassuiot/test/e2e/manage-cas"
	devices "github.com/lamassuiot/lamassuiot/test/e2e/manage-devices"
	dmss "github.com/lamassuiot/lamassuiot/test/e2e/manage-dms"
	certs "github.com/lamassuiot/lamassuiot/test/e2e/manager-certs"
)

var domain = flag.String("domain", "", "domain")
var cacert = flag.String("cert", "", "ca certificate")

func main() {
	flag.Parse()
	if *domain == "" || *cacert == "" {
		return
	}

	scaleIndex := 1
	scaleTest(scaleIndex, *cacert, *domain)
}

func scaleTest(scaleIndex int, certPath string, domain string) {
	fmt.Println("Scenario Manage CAs: " + strconv.Itoa(scaleIndex) + " CAs")
	ca, err := cas.ManageCAs(scaleIndex, scaleIndex, certPath, domain)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Scenario Industrial Environment: " + strconv.Itoa(scaleIndex) + " devices")
	dmsId, err := industrial.IndustrialEnvironment(ca.Name, scaleIndex, 1, certPath, domain)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Scenario Manage Devices")
	err = devices.ManageDevices(scaleIndex, certPath, domain)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Scenario Manage DMSs: " + strconv.Itoa(scaleIndex) + " DMSs")
	err = dmss.ManageDMSs(scaleIndex, dmsId, ca.Name, scaleIndex, certPath, domain)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Scenario Manage Certs")
	err = certs.ManageCerts(ca.Name, scaleIndex, certPath, domain)
	if err != nil {
		fmt.Println(err)
		return
	}
}
