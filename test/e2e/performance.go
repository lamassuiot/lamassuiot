package e2e

import (
	"fmt"

	industrial "github.com/lamassuiot/lamassuiot/test/e2e/industrial_Environment"
	cas "github.com/lamassuiot/lamassuiot/test/e2e/manage-cas"
	devices "github.com/lamassuiot/lamassuiot/test/e2e/manage-devices"
	dmss "github.com/lamassuiot/lamassuiot/test/e2e/manage-dms"
	certs "github.com/lamassuiot/lamassuiot/test/e2e/manager-certs"
)

func main() {
	scaleIndex := 1
	scaleTest(scaleIndex)

	scaleIndex = scaleIndex + 10
	scaleTest(scaleIndex)

	scaleIndex = scaleIndex + 20
	scaleTest(scaleIndex)

	scaleIndex = scaleIndex + 40
	scaleTest(scaleIndex)

	scaleIndex = scaleIndex + 30
	scaleTest(scaleIndex)
}

func scaleTest(scaleIndex int) {
	fmt.Println("Scenario Manage CAs: 100 CAs")
	ca, err := cas.ManageCAs(2*scaleIndex, scaleIndex)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Scenario Industrial Environment: 10000 devices")
	dmsId, err := industrial.IndustrialEnvironment(ca.Name, 10000*scaleIndex, 3)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Scenario Manage Devices")
	err = devices.ManageDevices(scaleIndex)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Scenario Manage DMSs: 100 DMSs")
	err = dmss.ManageDMSs(2*scaleIndex, dmsId, ca.Name, scaleIndex)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Scenario Manage Certs")
	err = certs.ManageCerts(ca.Name, scaleIndex)
	if err != nil {
		fmt.Println(err)
		return
	}
}
