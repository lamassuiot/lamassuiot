package assemblers

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

func StartDeviceManagerServiceTestServer(t *testing.T, withEventBus bool) (*DeviceManagerTestServer, error) {
	var err error
	eventBusConf := &TestEventBusConfig{
		config: config.EventBusEngine{
			Enabled: false,
		},
	}
	if withEventBus {
		eventBusConf, err = PrepareRabbitMQForTest()
		if err != nil {
			t.Fatalf("could not prepare RabbitMQ test server: %s", err)
		}
	}

	storageConfig, err := PreparePostgresForTest([]string{"ca", "devicemanager"})
	if err != nil {
		t.Fatalf("could not prepare Postgres test server: %s", err)
	}

	cryptoConfig := PrepareCryptoEnginesForTest([]CryptoEngine{GOLANG})
	testServer, err := AssembleServices(storageConfig, eventBusConf, cryptoConfig, []Service{CA, DEVICE_MANAGER})
	if err != nil {
		t.Fatalf("could not assemble Server with HTTP server")
	}
	err = testServer.BeforeEach()
	if err != nil {
		t.Fatalf("could not run 'BeforeEach' cleanup func in test case: %s", err)
	}

	t.Cleanup(testServer.AfterSuite)

	return testServer.DeviceManager, nil
}

func TestDuplicateDeviceCreation(t *testing.T) {
	dmgr, err := StartDeviceManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}
	deviceSample := services.CreateDeviceInput{
		ID:        "test",
		Alias:     "test",
		Tags:      []string{"test"},
		Metadata:  map[string]interface{}{"test": "test"},
		DMSID:     "test",
		Icon:      "test",
		IconColor: "#000000",
	}
	device, err := dmgr.Service.CreateDevice(deviceSample)
	if err != nil {
		t.Fatalf("could not create device: %s", err)
	}
	checkDevice(t, device, deviceSample)
	_, err = dmgr.Service.CreateDevice(deviceSample)
	if err == nil {
		t.Fatalf("duplicate device creation should fail")
	}
}

func TestPagination(t *testing.T) {
	dmgr, err := StartDeviceManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	deviceSample := services.CreateDeviceInput{
		ID:        "test",
		Alias:     "test",
		Tags:      []string{"test"},
		Metadata:  map[string]interface{}{"test": "test"},
		DMSID:     "test",
		Icon:      "test",
		IconColor: "#000000",
	}

	deviceSample2 := services.CreateDeviceInput{
		ID:        "test2",
		Alias:     "test2",
		Tags:      []string{"test2"},
		Metadata:  map[string]interface{}{"test2": "test2"},
		DMSID:     "test2",
		Icon:      "test2",
		IconColor: "#000001",
	}

	deviceSample3 := services.CreateDeviceInput{
		ID:        "test3",
		Alias:     "test3",
		Tags:      []string{"test3"},
		Metadata:  map[string]interface{}{"test3": "test3"},
		DMSID:     "test3",
		Icon:      "test3",
		IconColor: "#000002",
	}

	deviceSample4 := services.CreateDeviceInput{
		ID:        "test4",
		Alias:     "test4",
		Tags:      []string{"test4"},
		Metadata:  map[string]interface{}{"test4": "test4"},
		DMSID:     "test4",
		Icon:      "test4",
		IconColor: "#000003",
	}

	deviceSample5 := services.CreateDeviceInput{
		ID:        "test5",
		Alias:     "test5",
		Tags:      []string{"test5"},
		Metadata:  map[string]interface{}{"test5": "test5"},
		DMSID:     "test5",
		Icon:      "test5",
		IconColor: "#000004",
	}

	dmgr.Service.CreateDevice(deviceSample)
	dmgr.Service.CreateDevice(deviceSample2)
	dmgr.Service.CreateDevice(deviceSample3)
	dmgr.Service.CreateDevice(deviceSample4)
	dmgr.Service.CreateDevice(deviceSample5)

	devices := []models.Device{}
	request := services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: &resources.QueryParameters{
				PageSize: 2,
				Sort: resources.SortOptions{
					SortMode:  resources.SortModeAsc,
					SortField: "id",
				},
			},
			ExhaustiveRun: false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	}

	bookmark, err := dmgr.Service.GetDevices(request)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}
	if bookmark == "" {
		t.Fatalf("bookmark is empty")
	}
	if len(devices) != 2 {
		t.Fatalf("could not retrieve device: %s", err)
	}

	checkDevice(t, &devices[0], deviceSample)

	devices = []models.Device{}
	request = services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: &resources.QueryParameters{
				NextBookmark: bookmark,
				Sort: resources.SortOptions{
					SortMode:  resources.SortModeAsc,
					SortField: "id",
				},
			},
			ExhaustiveRun: false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	}

	bookmark, err = dmgr.Service.GetDevices(request)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}
	if bookmark == "" {
		t.Fatalf("bookmark is empty")
	}
	if len(devices) != 2 {
		t.Fatalf("could not retrieve device: %s", err)
	}

	checkDevice(t, &devices[0], deviceSample3)

	devices = []models.Device{}
	request = services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: &resources.QueryParameters{
				NextBookmark: bookmark,
				Sort: resources.SortOptions{
					SortMode:  resources.SortModeAsc,
					SortField: "id",
				},
			},
			ExhaustiveRun: false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	}

	bookmark, err = dmgr.Service.GetDevices(request)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}

	if len(devices) != 1 {
		t.Fatalf("could not retrieve device: %v", len(devices))
	}
	checkDevice(t, &devices[0], deviceSample5)

	devices = []models.Device{}
	request = services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: &resources.QueryParameters{
				NextBookmark: bookmark,
				Sort: resources.SortOptions{
					SortMode:  resources.SortModeAsc,
					SortField: "id",
				},
			},
			ExhaustiveRun: false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	}

	bookmark, err = dmgr.Service.GetDevices(request)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}

	if len(devices) != 0 {
		t.Fatalf("could not retrieve device: %v", len(devices))
	}

	if bookmark != "" {
		t.Fatalf("bookmark should be empty at last page %s", bookmark)
	}

	// Sort by id desc
	devices = []models.Device{}
	request = services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: &resources.QueryParameters{
				PageSize: 1,
				Sort: resources.SortOptions{
					SortMode:  resources.SortModeDesc,
					SortField: "id",
				},
			},
			ExhaustiveRun: false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	}

	_, err = dmgr.Service.GetDevices(request)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}
	checkDevice(t, &devices[0], deviceSample5)

}

func TestBasicDeviceManager(t *testing.T) {
	dmgr, err := StartDeviceManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	deviceSample := services.CreateDeviceInput{
		ID:        "test",
		Alias:     "test",
		Tags:      []string{"test"},
		Metadata:  map[string]interface{}{"test": "test"},
		DMSID:     "test",
		Icon:      "test",
		IconColor: "#000000",
	}

	deviceSample2 := services.CreateDeviceInput{
		ID:        "test2",
		Alias:     "test2",
		Tags:      []string{"test2"},
		Metadata:  map[string]interface{}{"test2": "test2"},
		DMSID:     "test2",
		Icon:      "test2",
		IconColor: "#000001",
	}

	device, err := dmgr.Service.CreateDevice(deviceSample)
	dmgr.Service.CreateDevice(deviceSample2)
	if err != nil {
		t.Fatalf("could not create device: %s", err)
	}
	checkDevice(t, device, deviceSample)

	request := services.GetDeviceByIDInput{ID: "test"}

	deviceGet, err := dmgr.Service.GetDeviceByID(request)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}
	checkDevice(t, deviceGet, deviceSample)

	checkSelectAll(t, dmgr)

	checkSelectByDMS(t, dmgr, deviceSample2)
	checkDeviceStats(t, dmgr)
	checkUpdateDeviceStatus(t, dmgr, deviceSample)
	checkUpdateDeviceMetadata(t, dmgr, deviceSample)

}

func checkUpdateDeviceMetadata(t *testing.T, dmgr *DeviceManagerTestServer, deviceSample services.CreateDeviceInput) {
	request := services.UpdateDeviceMetadataInput{
		ID:       deviceSample.ID,
		Metadata: map[string]interface{}{"test": "test2"},
	}

	device, err := dmgr.Service.UpdateDeviceMetadata(request)
	if err != nil {
		t.Fatalf("could not update device metadata: %s", err)
	}

	if device.Metadata["test"] != "test2" {
		t.Fatalf("device metadata mismatch: expected %s, got %s", "test2", device.Metadata["test"])
	}
}

func checkUpdateDeviceStatus(t *testing.T, dmgr *DeviceManagerTestServer, deviceSample services.CreateDeviceInput) {
	request := services.UpdateDeviceStatusInput{
		ID:        deviceSample.ID,
		NewStatus: models.DeviceActive,
	}

	device, err := dmgr.Service.UpdateDeviceStatus(request)
	if err != nil {
		t.Fatalf("could not update device status: %s", err)
	}

	if device.Status != models.DeviceActive {
		t.Fatalf("device status mismatch: expected %s, got %s", models.DeviceActive, device.Status)
	}
}

func checkDeviceStats(t *testing.T, dmgr *DeviceManagerTestServer) {

	request := services.GetDevicesStatsInput{}

	stats, err := dmgr.Service.GetDevicesStats(request)
	if err != nil {
		t.Fatalf("could not retrieve device stats: %s", err)
	}

	if stats.TotalDevices != 2 {
		t.Fatalf("device stats mismatch: expected %d, got %d", 2, stats.TotalDevices)
	}

	if stats.DevicesStatus[models.DeviceNoIdentity] != 2 {
		t.Fatalf("device stats mismatch: expected %d, got %d", 2, stats.DevicesStatus[models.DeviceNoIdentity])
	}

	if stats.DevicesStatus[models.DeviceActive] != 0 {
		t.Fatalf("device stats mismatch: expected %d, got %d", 0, stats.DevicesStatus[models.DeviceActive])
	}
}

func checkDevice(t *testing.T, device *models.Device, deviceSample services.CreateDeviceInput) {
	if device.ID != deviceSample.ID {
		t.Fatalf("device id mismatch: expected %s, got %s", deviceSample.ID, device.ID)
	}

	if device.Icon != deviceSample.Icon {
		t.Fatalf("device icon mismatch: expected %s, got %s", deviceSample.Icon, device.Icon)
	}

	if device.IconColor != deviceSample.IconColor {
		t.Fatalf("device icon mismatch: expected %s, got %s", deviceSample.IconColor, device.IconColor)
	}

	if device.Status != models.DeviceNoIdentity {
		t.Fatalf("device status mismatch: expected %s, got %s", models.DeviceNoIdentity, device.Status)
	}

	if device.DMSOwner != deviceSample.DMSID {
		t.Fatalf("device dms id mismatch: expected %s, got %s", deviceSample.DMSID, device.DMSOwner)
	}

	if device.Tags[0] != deviceSample.Tags[0] {
		t.Fatalf("device tags mismatch: expected %s, got %s", deviceSample.Tags[0], device.Tags[0])
	}

	if device.CreationTimestamp.IsZero() {
		t.Fatalf("device creation timestamp is zero")
	}

	if device.Events == nil {
		t.Fatalf("device events is nil")
	}

	if device.IdentitySlot != nil {
		t.Fatalf("device identity slot is not nil")
	}
}

func checkSelectByDMS(t *testing.T, dmgr *DeviceManagerTestServer, deviceSample services.CreateDeviceInput) {
	devices := []models.Device{}
	request2 := services.GetDevicesByDMSInput{
		DMSID: "test2",
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: nil,
			ExhaustiveRun:   false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	}

	_, err := dmgr.Service.GetDeviceByDMS(request2)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}

	if len(devices) != 1 {
		t.Fatalf("could not retrieve device: %s", err)
	}

	checkDevice(t, &devices[0], deviceSample)
}

func checkSelectAll(t *testing.T, dmgr *DeviceManagerTestServer) {
	devices := []models.Device{}
	request2 := services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: nil,
			ExhaustiveRun:   false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	}

	_, err := dmgr.Service.GetDevices(request2)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}

	if len(devices) != 2 {
		t.Fatalf("could not retrieve device: %s", err)
	}
}
