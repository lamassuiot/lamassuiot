package assemblers

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	identityextractors "github.com/lamassuiot/lamassuiot/v2/pkg/routes/middlewares/identity-extractors"
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

func TestGetAllDevices(t *testing.T) {
	// t.Parallel()
	ctx := context.Background()
	dmgr, err := StartDeviceManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}
	deviceSample1 := services.CreateDeviceInput{
		ID:        "test",
		Alias:     "test",
		Tags:      []string{"test"},
		Metadata:  map[string]interface{}{"test": "test"},
		DMSID:     "test",
		Icon:      "test",
		IconColor: "#000000",
	}
	_, err = dmgr.Service.CreateDevice(ctx, deviceSample1)
	if err != nil {
		t.Fatalf("could not create device: %s", err)
	}

	deviceSample2 := services.CreateDeviceInput{
		ID:        "test2",
		Alias:     "test2",
		Tags:      []string{"test"},
		Metadata:  map[string]interface{}{"test": "test"},
		DMSID:     "test",
		Icon:      "test",
		IconColor: "#000000",
	}
	_, err = dmgr.Service.CreateDevice(ctx, deviceSample2)
	if err != nil {
		t.Fatalf("could not create device: %s", err)
	}

	deviceSample3 := services.CreateDeviceInput{
		ID:        "test3",
		Alias:     "test3",
		Tags:      []string{"test"},
		Metadata:  map[string]interface{}{"test": "test"},
		DMSID:     "test",
		Icon:      "test",
		IconColor: "#000000",
	}
	_, err = dmgr.Service.CreateDevice(ctx, deviceSample3)
	if err != nil {
		t.Fatalf("could not create device: %s", err)
	}

	var testcases = []struct {
		name        string
		run         func() ([]models.Device, error)
		resultCheck func(devices []models.Device, err error)
	}{
		{
			name: "OK/PaginationWithoutExhaustiveRun",
			run: func() ([]models.Device, error) {
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

				_, err := dmgr.HttpDeviceManagerSDK.GetDevices(context.Background(), request)
				if err != nil {
					t.Fatalf("could not retrieve a device: %s", err)
				}
				return devices, nil
			},
			resultCheck: func(devices []models.Device, err error) {
				if len(devices) != 2 {
					t.Fatalf("The amount is two, got %d", len(devices))
				}
			},
		},
		{
			name: "OK/PaginationExhautsiveRun",
			run: func() ([]models.Device, error) {
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
						ExhaustiveRun: true,
						ApplyFunc: func(dev models.Device) {
							devices = append(devices, dev)
						},
					},
				}

				_, err := dmgr.HttpDeviceManagerSDK.GetDevices(context.Background(), request)
				if err != nil {
					t.Fatalf("could not retrieve a device: %s", err)
				}
				return devices, nil
			},
			resultCheck: func(devices []models.Device, err error) {
				if len(devices) != 3 {
					t.Fatalf("The amount is three, got %d", len(devices))
				}
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			tc.resultCheck(tc.run())
		})
	}
}

func TestGetDeviceStats(t *testing.T) {
	// t.Parallel()
	ctx := context.Background()
	dmgr, err := StartDeviceManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}
	deviceSample1 := services.CreateDeviceInput{
		ID:        "test",
		Alias:     "test",
		Tags:      []string{"test"},
		Metadata:  map[string]interface{}{"test": "test"},
		DMSID:     "test",
		Icon:      "test",
		IconColor: "#000000",
	}
	_, err = dmgr.Service.CreateDevice(ctx, deviceSample1)
	if err != nil {
		t.Fatalf("could not create device: %s", err)
	}

	deviceSample2 := services.CreateDeviceInput{
		ID:        "test2",
		Alias:     "test2",
		Tags:      []string{"test"},
		Metadata:  map[string]interface{}{"test": "test"},
		DMSID:     "test",
		Icon:      "test",
		IconColor: "#000000",
	}
	_, err = dmgr.Service.CreateDevice(ctx, deviceSample2)
	if err != nil {
		t.Fatalf("could not create device: %s", err)
	}

	deviceSample3 := services.CreateDeviceInput{
		ID:        "test3",
		Alias:     "test3",
		Tags:      []string{"test"},
		Metadata:  map[string]interface{}{"test": "test"},
		DMSID:     "test",
		Icon:      "test",
		IconColor: "#000000",
	}
	_, err = dmgr.Service.CreateDevice(ctx, deviceSample3)
	if err != nil {
		t.Fatalf("could not create device: %s", err)
	}

	var testcases = []struct {
		name        string
		run         func() (*models.DevicesStats, error)
		resultCheck func(*models.DevicesStats, error)
	}{
		{
			name: "OK/GetDevicesStats",
			run: func() (*models.DevicesStats, error) {

				devsStats, err := dmgr.HttpDeviceManagerSDK.GetDevicesStats(context.Background(), services.GetDevicesStatsInput{})
				if err != nil {
					t.Fatalf("could not retrieve a device: %s", err)
				}
				return devsStats, nil
			},
			resultCheck: func(stats *models.DevicesStats, err error) {
				if stats == nil {
					t.Fatalf("The stastics are nil")
				}
				if err != nil {
					t.Fatalf("not expected error. Got an error")
				}
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			tc.resultCheck(tc.run())
		})
	}
}

func TestGetDevicesByDMS(t *testing.T) {
	// t.Parallel()
	ctx := context.Background()
	dmgr, err := StartDeviceManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create Dms Manager test server: %s", err)
	}

	createDMS := func(modifier func(in *services.CreateDMSInput)) (*models.DMS, error) {
		input := services.CreateDMSInput{
			ID:       uuid.NewString(),
			Name:     "MyIotFleet",
			Metadata: map[string]any{},
			Settings: models.DMSSettings{
				EnrollmentSettings: models.EnrollmentSettings{
					EnrollmentProtocol: models.EST,
					EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
						AuthMode: models.ESTAuthMode(identityextractors.IdentityExtractorClientCertificate),
						AuthOptionsMTLS: models.AuthOptionsClientCertificate{
							ChainLevelValidation: -1,
							ValidationCAs:        []string{},
						},
					},
					DeviceProvisionProfile: models.DeviceProvisionProfile{
						Icon:      "BiSolidCreditCardFront",
						IconColor: "#25ee32-#222222",
						Metadata:  map[string]any{},
						Tags:      []string{"iot", "testdms", "cloud"},
					},
					RegistrationMode:            models.JITP,
					EnableReplaceableEnrollment: true,
				},
				ReEnrollmentSettings: models.ReEnrollmentSettings{
					AdditionalValidationCAs:     []string{},
					ReEnrollmentDelta:           models.TimeDuration(time.Hour),
					EnableExpiredRenewal:        true,
					PreventiveReEnrollmentDelta: models.TimeDuration(time.Minute * 3),
					CriticalReEnrollmentDelta:   models.TimeDuration(time.Minute * 2),
				},
				CADistributionSettings: models.CADistributionSettings{
					IncludeLamassuSystemCA: true,
					IncludeEnrollmentCA:    true,
					ManagedCAs:             []string{},
				},
			},
		}

		modifier(&input)

		return dmsMgr.Service.CreateDMS(context.Background(), input)

	}

	var testcases = []struct {
		name        string
		run         func() ([]models.Device, error)
		resultCheck func(devices []models.Device, err error)
	}{
		{
			name: "OK/PaginationWithoutExhaustiveRun",
			run: func() ([]models.Device, error) {

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

				dms, err := createDMS(func(in *services.CreateDMSInput) {})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}
				deviceSample1 := services.CreateDeviceInput{
					ID:        "test",
					Alias:     "test",
					Tags:      []string{"test"},
					Metadata:  map[string]interface{}{"test": "test"},
					DMSID:     dms.ID,
					Icon:      "test",
					IconColor: "#000000",
				}
				_, err = dmgr.Service.CreateDevice(ctx, deviceSample1)
				if err != nil {
					t.Fatalf("could not create device: %s", err)
				}

				deviceSample2 := services.CreateDeviceInput{
					ID:        "test2",
					Alias:     "test2",
					Tags:      []string{"test"},
					Metadata:  map[string]interface{}{"test": "test"},
					DMSID:     dms.ID,
					Icon:      "test",
					IconColor: "#000000",
				}
				_, err = dmgr.Service.CreateDevice(ctx, deviceSample2)
				if err != nil {
					t.Fatalf("could not create device: %s", err)
				}

				deviceSample3 := services.CreateDeviceInput{
					ID:        "test3",
					Alias:     "test3",
					Tags:      []string{"test"},
					Metadata:  map[string]interface{}{"test": "test"},
					DMSID:     dms.ID,
					Icon:      "test",
					IconColor: "#000000",
				}
				_, err = dmgr.Service.CreateDevice(ctx, deviceSample3)
				if err != nil {
					t.Fatalf("could not create device: %s", err)
				}

				_, err = dmgr.Service.GetDeviceByDMS(ctx, services.GetDevicesByDMSInput{
					DMSID:     dms.ID,
					ListInput: request.ListInput,
				})

				if err != nil {
					t.Fatalf("could not retrieve a device: %s", err)
				}

				return devices, nil
			},
			resultCheck: func(devices []models.Device, err error) {
				if len(devices) != 2 {
					t.Fatalf("The amount is three, got %d", len(devices))
				}
			},
		},
		{
			name: "OK/PaginationWithExhaustiveRun",
			run: func() ([]models.Device, error) {

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
						ExhaustiveRun: true,
						ApplyFunc: func(dev models.Device) {
							devices = append(devices, dev)
						},
					},
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}
				deviceSample1 := services.CreateDeviceInput{
					ID:        "test11",
					Alias:     "test",
					Tags:      []string{"test"},
					Metadata:  map[string]interface{}{"test": "test"},
					DMSID:     dms.ID,
					Icon:      "test",
					IconColor: "#000000",
				}
				_, err = dmgr.Service.CreateDevice(ctx, deviceSample1)
				if err != nil {
					t.Fatalf("could not create device: %s", err)
				}

				deviceSample2 := services.CreateDeviceInput{
					ID:        "test12",
					Alias:     "test2",
					Tags:      []string{"test"},
					Metadata:  map[string]interface{}{"test": "test"},
					DMSID:     dms.ID,
					Icon:      "test",
					IconColor: "#000000",
				}
				_, err = dmgr.Service.CreateDevice(ctx, deviceSample2)
				if err != nil {
					t.Fatalf("could not create device: %s", err)
				}

				deviceSample3 := services.CreateDeviceInput{
					ID:        "test13",
					Alias:     "test3",
					Tags:      []string{"test"},
					Metadata:  map[string]interface{}{"test": "test"},
					DMSID:     dms.ID,
					Icon:      "test",
					IconColor: "#000000",
				}
				_, err = dmgr.Service.CreateDevice(ctx, deviceSample3)
				if err != nil {
					t.Fatalf("could not create device: %s", err)
				}

				_, err = dmgr.Service.GetDeviceByDMS(ctx, services.GetDevicesByDMSInput{
					DMSID:     dms.ID,
					ListInput: request.ListInput,
				})

				if err != nil {
					t.Fatalf("could not retrieve a device: %s", err)
				}

				return devices, nil
			},
			resultCheck: func(devices []models.Device, err error) {
				if len(devices) != 3 {
					t.Fatalf("The amount is three, got %d", len(devices))
				}
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			tc.resultCheck(tc.run())
		})
	}
}

func TestDuplicateDeviceCreation(t *testing.T) {
	ctx := context.Background()
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
	device, err := dmgr.Service.CreateDevice(ctx, deviceSample)
	if err != nil {
		t.Fatalf("could not create device: %s", err)
	}
	checkDevice(t, device, deviceSample)
	_, err = dmgr.Service.CreateDevice(ctx, deviceSample)
	if err == nil {
		t.Fatalf("duplicate device creation should fail")
	}
}

func TestPagination(t *testing.T) {
	ctx := context.Background()
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

	dmgr.Service.CreateDevice(ctx, deviceSample)
	dmgr.Service.CreateDevice(ctx, deviceSample2)
	dmgr.Service.CreateDevice(ctx, deviceSample3)
	dmgr.Service.CreateDevice(ctx, deviceSample4)
	dmgr.Service.CreateDevice(ctx, deviceSample5)

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

	bookmark, err := dmgr.Service.GetDevices(ctx, request)
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

	bookmark, err = dmgr.Service.GetDevices(ctx, request)
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

	bookmark, err = dmgr.Service.GetDevices(ctx, request)
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

	bookmark, err = dmgr.Service.GetDevices(ctx, request)
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

	_, err = dmgr.Service.GetDevices(ctx, request)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}
	checkDevice(t, &devices[0], deviceSample5)

}

func TestBasicDeviceManager(t *testing.T) {
	ctx := context.Background()

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

	device, err := dmgr.Service.CreateDevice(ctx, deviceSample)
	dmgr.Service.CreateDevice(ctx, deviceSample2)
	if err != nil {
		t.Fatalf("could not create device: %s", err)
	}
	checkDevice(t, device, deviceSample)

	request := services.GetDeviceByIDInput{ID: "test"}

	deviceGet, err := dmgr.Service.GetDeviceByID(ctx, request)
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
	ctx := context.Background()

	request := services.UpdateDeviceMetadataInput{
		ID:       deviceSample.ID,
		Metadata: map[string]interface{}{"test": "test2"},
	}

	device, err := dmgr.Service.UpdateDeviceMetadata(ctx, request)
	if err != nil {
		t.Fatalf("could not update device metadata: %s", err)
	}

	if device.Metadata["test"] != "test2" {
		t.Fatalf("device metadata mismatch: expected %s, got %s", "test2", device.Metadata["test"])
	}
}

func checkUpdateDeviceStatus(t *testing.T, dmgr *DeviceManagerTestServer, deviceSample services.CreateDeviceInput) {
	ctx := context.Background()
	request := services.UpdateDeviceStatusInput{
		ID:        deviceSample.ID,
		NewStatus: models.DeviceActive,
	}

	device, err := dmgr.Service.UpdateDeviceStatus(ctx, request)
	if err != nil {
		t.Fatalf("could not update device status: %s", err)
	}

	if device.Status != models.DeviceActive {
		t.Fatalf("device status mismatch: expected %s, got %s", models.DeviceActive, device.Status)
	}
}

func checkDeviceStats(t *testing.T, dmgr *DeviceManagerTestServer) {
	ctx := context.Background()
	request := services.GetDevicesStatsInput{}

	stats, err := dmgr.Service.GetDevicesStats(ctx, request)
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
	ctx := context.Background()

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

	_, err := dmgr.Service.GetDeviceByDMS(ctx, request2)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}

	if len(devices) != 1 {
		t.Fatalf("could not retrieve device: %s", err)
	}

	checkDevice(t, &devices[0], deviceSample)
}

func checkSelectAll(t *testing.T, dmgr *DeviceManagerTestServer) {
	ctx := context.Background()

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

	_, err := dmgr.Service.GetDevices(ctx, request2)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}

	if len(devices) != 2 {
		t.Fatalf("could not retrieve device: %s", err)
	}
}
