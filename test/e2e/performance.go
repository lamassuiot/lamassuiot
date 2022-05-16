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

	scaleIndex = scaleIndex + 10
	scaleTest(scaleIndex, *cacert, *domain)

	scaleIndex = scaleIndex + 20
	scaleTest(scaleIndex, *cacert, *domain)

	scaleIndex = scaleIndex + 40
	scaleTest(scaleIndex, *cacert, *domain)

	scaleIndex = scaleIndex + 30
	scaleTest(scaleIndex, *cacert, *domain)
}

func scaleTest(scaleIndex int, certPath string, domain string) {
	fmt.Println("Scenario Manage CAs: " + strconv.Itoa(2*scaleIndex) + " CAs")
	ca, err := cas.ManageCAs(2*scaleIndex, scaleIndex, certPath, domain)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Scenario Industrial Environment: " + strconv.Itoa(10000*scaleIndex) + " devices")
	dmsId, err := industrial.IndustrialEnvironment(ca.Name, 10000*scaleIndex, 3, certPath, domain)
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

	fmt.Println("Scenario Manage DMSs: " + strconv.Itoa(2*scaleIndex) + " DMSs")
	err = dmss.ManageDMSs(2*scaleIndex, dmsId, ca.Name, scaleIndex, certPath, domain)
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
