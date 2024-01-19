package assemblers

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/clients"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
	postgres_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/storage/postgres"
)

type DeviceManagerTestServer struct {
	Service              services.DeviceManagerService
	HttpDeviceManagerSDK services.DeviceManagerService
	BeforeEach           func() error
	AfterSuite           func()
}

func initPostgres(dbs []string) (config.PostgresPSEConfig, postgres_test.PostgresSuite) {
	return postgres_test.BeforeSuite(dbs)
}

func buildCASimpleTestServer(pConfig config.PostgresPSEConfig, postgresSuite postgres_test.PostgresSuite) (*CATestServer, error) {

	svc, port, err := AssembleCAServiceWithHTTPServer(config.CAConfig{
		BaseConfig: config.BaseConfig{
			Logs: config.BaseConfigLogging{
				Level: config.Info,
			},
			Server: config.HttpServer{
				LogLevel:           config.Info,
				HealthCheckLogging: false,
				Protocol:           config.HTTP,
			},
			EventBus: config.EventBusEngine{Enabled: false},
		},
		Storage: config.PluggableStorageEngine{
			LogLevel: config.Info,
			Provider: config.Postgres,
			Postgres: pConfig,
		},
		CryptoEngines: config.CryptoEngines{
			LogLevel:      config.Info,
			DefaultEngine: "filesystem-1",
			GolangProvider: []config.GolangEngineConfig{
				{
					ID:               "filesystem-1",
					Metadata:         map[string]interface{}{},
					StorageDirectory: "/tmp/lms-test/",
				},
			},
		},
		CryptoMonitoring: config.CryptoMonitoring{
			Enabled: false,
		},
		VAServerDomain: "http://dev.lamassu.test",
	}, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})

	if err != nil {
		return nil, fmt.Errorf("could not assemble CA with HTTP server")
	}

	return &CATestServer{
		Service:   *svc,
		HttpCASDK: clients.NewHttpCAClient(http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			//reinitialize tables schemas
			_, err = postgres.NewCAPostgresRepository(postgresSuite.DB["ca"])
			if err != nil {
				return fmt.Errorf("could not run reinitialize CA tables: %s", err)
			}

			_, err = postgres.NewCertificateRepository(postgresSuite.DB["ca"])
			if err != nil {
				return fmt.Errorf("could not run reinitialize Certificates tables: %s", err)
			}

			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP CA")
			postgresSuite.AfterSuite()
		},
	}, nil
}

func BuildDeviceManagerServiceTestServer(t *testing.T) (*DeviceManagerTestServer, error) {
	pConfig, postgresSuite := initPostgres([]string{"ca", "devicemanager"})

	caTest, err := buildCASimpleTestServer(pConfig, postgresSuite)
	if err != nil {
		return nil, fmt.Errorf("could not create CA test server: %s", err)
	}
	t.Cleanup(caTest.AfterSuite)

	svc, port, err := AssembleDeviceManagerServiceWithHTTPServer(config.DeviceManagerConfig{
		BaseConfig: config.BaseConfig{
			Logs: config.BaseConfigLogging{
				Level: config.Info,
			},
			Server: config.HttpServer{
				LogLevel:           config.Info,
				HealthCheckLogging: false,
				Protocol:           config.HTTP,
			},
			EventBus: config.EventBusEngine{Enabled: false},
		},
		Storage: config.PluggableStorageEngine{
			LogLevel: config.Info,
			Provider: config.Postgres,
			Postgres: pConfig,
		},
	}, caTest.Service, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})
	if err != nil {
		return nil, fmt.Errorf("could not assemble Device Manager Service. Exiting: %s", err)
	}

	return &DeviceManagerTestServer{
		Service:              *svc,
		HttpDeviceManagerSDK: clients.NewHttpDeviceManagerClient(http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			err := postgresSuite.BeforeEach()
			if err != nil {
				return fmt.Errorf("could not run postgres BeforeEach: %s", err)
			}

			err = caTest.BeforeEach()
			if err != nil {
				return fmt.Errorf("could not run postgres BeforeEach: %s", err)
			}

			//reinitialize tables schemas
			_, err = postgres.NewDeviceManagerRepository(postgresSuite.DB["devicemanager"])
			if err != nil {
				return fmt.Errorf("could not run reinitialize Certificates tables: %s", err)
			}

			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP DEVICE MANAGER")
			postgresSuite.AfterSuite()
		},
	}, nil

}

func TestDuplicateDeviceCreation(t *testing.T) {
	dmgr, err := BuildDeviceManagerServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}
	t.Cleanup(dmgr.AfterSuite)
	err = dmgr.BeforeEach()
	if err != nil {
		t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
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
	dmgr, err := BuildDeviceManagerServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}
	t.Cleanup(dmgr.AfterSuite)
	err = dmgr.BeforeEach()
	if err != nil {
		t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
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
	dmgr, err := BuildDeviceManagerServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(dmgr.AfterSuite)
	err = dmgr.BeforeEach()
	if err != nil {
		t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
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

	if device.DMSOwnerID != deviceSample.DMSID {
		t.Fatalf("device dms id mismatch: expected %s, got %s", deviceSample.DMSID, device.DMSOwnerID)
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
