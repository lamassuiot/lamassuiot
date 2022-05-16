package dmss

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/jakehl/goid"
	devdto "github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	lamassuenroller "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/client"
	dmsDTO "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/test/e2e/utils"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"
)

func ManageDMSs(dmsNumber int, dmsid string, caName string, scaleIndex int, certPath string, domain string) error {
	var f, _ = os.Create("./manage-dms/GetDMSs_" + strconv.Itoa(scaleIndex) + ".csv")
	var f1, _ = os.Create("./manage-dms/GetDMSbyID_" + strconv.Itoa(scaleIndex) + ".csv")
	var f2, _ = os.Create("./manage-dms/GetDmsCertHistory_" + strconv.Itoa(scaleIndex) + ".csv")
	var f3, _ = os.Create("./manage-dms/GetDmsLastIssuedCert_" + strconv.Itoa(scaleIndex) + ".csv")
	var f4, _ = os.Create("./manage-dms/GetDevicesbyDMS_" + strconv.Itoa(scaleIndex) + ".csv")
	dmsClient, err := client.LamassuDmsClient(certPath, domain)
	if err != nil {
		fmt.Println(err)
		return err
	}
	var dms dmsDTO.DMS
	for i := 0; i < dmsNumber; i++ {
		dmsName := goid.NewV4UUID().String()
		_, dms, err := dmsClient.CreateDMSForm(context.Background(), dmsDTO.Subject{CN: dmsName}, dmsDTO.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dmsName)
		if err != nil {
			fmt.Println(err)
			return err
		}

		dms, err = dmsClient.UpdateDMSStatus(context.Background(), "APPROVED", dms.Id, []string{caName})
		if err != nil {
			fmt.Println(err)
			return err
		}
		err = LatencyGetDMSs(dmsClient, f)
		if err != nil {
			fmt.Println(err)
			return err
		}

	}

	err = dmsClient.DeleteDMS(context.Background(), dms.Id)
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = LatencyGetDMSbyID(dmsid, dmsClient, f1)
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = LatencyGetDMSCertHistory(f2, certPath, domain)
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = LatencyGetDMSLastIssuedCert(f3, certPath, domain)
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = LatencyGetDevicesbyDMS(dmsid, f4, certPath, domain)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}

func LatencyGetDMSs(dmsClient lamassuenroller.LamassuEnrollerClient, f *os.File) error {
	var max, min float64
	max = 0
	min = 12
	var totalDmss int
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		dmss, err := dmsClient.GetDMSs(context.Background())
		if err != nil {
			fmt.Println(err)
			return err
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		totalDmss = len(dmss)
	}
	media := (max + min) / 2
	err := utils.WriteDataFile(strconv.Itoa(totalDmss), max, min, media, f)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}

func LatencyGetDMSbyID(dmsid string, dmsClient lamassuenroller.LamassuEnrollerClient, f *os.File) error {
	var max, min float64
	max = 0
	min = 12
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		_, err := dmsClient.GetDMSbyID(context.Background(), dmsid)
		if err != nil {
			fmt.Println(err)
			return err
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
	}
	media := (max + min) / 2
	err := utils.WriteDataFile(dmsid, max, min, media, f)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func LatencyGetDMSCertHistory(f *os.File, certPath string, domain string) error {
	devClient, err := client.LamassuDevClient(certPath, domain)
	var max, min float64
	max = 0
	min = 12
	var totalhistory int
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		history, err := devClient.GetDmsCertHistoryThirtyDays(context.Background(), devdto.QueryParameters{Filter: "", Order: devdto.OrderOptions{Order: "DESC", Field: "id"}, Pagination: devdto.PaginationOptions{Page: 1, Offset: 50}})
		if err != nil {
			fmt.Println(err)
			return err
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		totalhistory = len(history)
	}
	media := (max + min) / 2
	err = utils.WriteDataFile(strconv.Itoa(totalhistory), max, min, media, f)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func LatencyGetDMSLastIssuedCert(f *os.File, certPath string, domain string) error {
	devClient, err := client.LamassuDevClient(certPath, domain)
	var max, min float64
	max = 0
	min = 12
	var totalissuedcert int
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		certs, err := devClient.GetDmsLastIssuedCert(context.Background(), devdto.QueryParameters{Filter: "", Order: devdto.OrderOptions{Order: "DESC", Field: "id"}, Pagination: devdto.PaginationOptions{Page: 1, Offset: 50}})
		if err != nil {
			fmt.Println(err)
			return err
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		totalissuedcert = len(certs)
	}
	media := (max + min) / 2
	err = utils.WriteDataFile(strconv.Itoa(totalissuedcert), max, min, media, f)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func LatencyGetDevicesbyDMS(dmsid string, f *os.File, certPath string, domain string) error {
	devClient, err := client.LamassuDevClient(certPath, domain)
	var max, min float64
	max = 0
	min = 12
	var totaldevices int
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		devices, err := devClient.GetDevicesByDMS(context.Background(), dmsid, devdto.QueryParameters{Filter: "", Order: devdto.OrderOptions{Order: "DESC", Field: "id"}, Pagination: devdto.PaginationOptions{Page: 1, Offset: 50}})
		if err != nil {
			fmt.Println(err)
			return err
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		totaldevices = len(devices)
	}
	media := (max + min) / 2
	err = utils.WriteDataFile(strconv.Itoa(totaldevices), max, min, media, f)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}
