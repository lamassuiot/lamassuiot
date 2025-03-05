package assemblers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"

	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
)

func StartDeviceManagerServiceTestServer(t *testing.T, withEventBus bool) (*DeviceManagerTestServer, error) {
	builder := TestServiceBuilder{}.WithDatabase("ca", "devicemanager").WithService(CA, DEVICE_MANAGER)
	if withEventBus {
		builder = builder.WithEventBus()
	}
	testServer, err := builder.Build(t)
	if err != nil {
		return nil, fmt.Errorf("could not create Device Manager test server: %s", err)
	}
	return testServer.DeviceManager, nil
}

func TestGetAllDevices(t *testing.T) {
	// t.Parallel()
	devsIds := [3]string{"test1", "test2", "test3"}
	ctx := context.Background()
	dmgr, err := StartDeviceManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}
	deviceSample1 := services.CreateDeviceInput{
		ID:        devsIds[0],
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
		ID:        devsIds[1],
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
		ID:        devsIds[2],
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
				check := 0
				if len(devices) != 2 {
					t.Fatalf("the amount is two, got %d", len(devices))
				}
				devTest := devsIds[:2]
				for _, id := range devTest {
					contains := slices.ContainsFunc(devices, func(device models.Device) bool {
						fmt.Println(device.ID)
						return device.ID == id
					})
					if contains != true {
						t.Fatalf("the device id is not of this test")
					} else {
						check += 1
					}
				}
				if check != 2 {
					t.Fatalf("device with a different id")
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
				check := 0
				if len(devices) != 3 {
					t.Fatalf("the amount is three, got %d", len(devices))
				}
				for _, id := range devsIds {
					contains := slices.ContainsFunc(devices, func(device models.Device) bool {
						return device.ID == id
					})
					if contains != true {
						t.Fatalf("the device id is not of this test")
					} else {
						check += 1
					}
				}
				if check != 3 {
					t.Fatalf("device with a different id")
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
	devsIds := [3]string{"test1", "test2", "test3"}
	// t.Parallel()
	ctx := context.Background()
	dmgr, err := StartDeviceManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}
	deviceSample1 := services.CreateDeviceInput{
		ID:        devsIds[0],
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
		ID:        devsIds[1],
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
		ID:        devsIds[2],
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
					t.Fatalf("the stastics are nil")
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

func TestGetDeviceByID(t *testing.T) {

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

	var testcases = []struct {
		name        string
		run         func() (*models.Device, error)
		resultCheck func(*models.Device, error)
	}{
		{
			name: "OK/GetDeviceByID",
			run: func() (*models.Device, error) {

				device, err := dmgr.HttpDeviceManagerSDK.GetDeviceByID(ctx, services.GetDeviceByIDInput{
					ID: "test",
				})
				if err != nil {
					t.Fatalf("could not retrieve a device: %s", err)
				}
				return device, nil
			},
			resultCheck: func(device *models.Device, err error) {
				if device == nil {
					t.Fatalf("the device has not been found")
				}
				if err != nil {
					t.Fatalf("not expected error. Got an error")
				}
				if device.ID != "test" {
					t.Fatalf("The iD of the devices is not correct")
				}
			},
		},
		{
			name: "Err/IDDoesNotExist",
			run: func() (*models.Device, error) {

				device, err := dmgr.HttpDeviceManagerSDK.GetDeviceByID(ctx, services.GetDeviceByIDInput{
					ID: "error",
				})

				return device, err
			},
			resultCheck: func(device *models.Device, err error) {
				if err == nil {
					t.Fatalf("expected error. Got not an error")
				}
				if !errors.Is(err, errs.ErrDeviceNotFound) {
					t.Fatalf("Unexpected error %s", err)
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

func TestUpdateDeviceMetadata(t *testing.T) {
	// t.Parallel()

	ctx := context.Background()
	dmgr, err := StartDeviceManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}
	deviceUpdMeta := map[string]any{
		"test":    "test",
		"lamassu": "lamassu",
		"arr":     []interface{}{"test", "test2"},
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

	var testcases = []struct {
		name        string
		run         func() (*models.Device, error)
		resultCheck func(device *models.Device, err error)
	}{
		{
			name: "OK/DeviceNotExist",
			run: func() (*models.Device, error) {

				device, err := dmgr.HttpDeviceManagerSDK.UpdateDeviceMetadata(context.Background(), services.UpdateDeviceMetadataInput{
					ID: "test",
					Patches: helpers.NewPatchBuilder().
						Add(helpers.JSONPointerBuilder(), deviceUpdMeta).
						Build(),
				})
				if err != nil {
					t.Fatalf("could not retrieve a device: %s", err)
				}
				return device, nil
			},
			resultCheck: func(device *models.Device, err error) {
				for key, value := range device.Metadata {
					if val, ok := deviceUpdMeta[key]; !ok || !reflect.DeepEqual(val, value) {
						t.Fatalf("the device´s metadata is not correct: %s != %s", val, value)
					}
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
	devDMS1 := [3]string{"test1", "test2", "test3"}
	devDMS2 := [3]string{"test11", "test12", "test13"}
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
				ServerKeyGen: models.ServerKeyGenSettings{
					Enabled: false,
				},
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

		return dmsMgr.HttpDeviceManagerSDK.CreateDMS(context.Background(), input)

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
					ID:        devDMS1[0],
					Alias:     "test",
					Tags:      []string{"test"},
					Metadata:  map[string]interface{}{"test": "test"},
					DMSID:     dms.ID,
					Icon:      "test",
					IconColor: "#000000",
				}
				_, err = dmgr.HttpDeviceManagerSDK.CreateDevice(ctx, deviceSample1)
				if err != nil {
					t.Fatalf("could not create device: %s", err)
				}

				deviceSample2 := services.CreateDeviceInput{
					ID:        devDMS1[1],
					Alias:     "test2",
					Tags:      []string{"test"},
					Metadata:  map[string]interface{}{"test": "test"},
					DMSID:     dms.ID,
					Icon:      "test",
					IconColor: "#000000",
				}
				_, err = dmgr.HttpDeviceManagerSDK.CreateDevice(ctx, deviceSample2)
				if err != nil {
					t.Fatalf("could not create device: %s", err)
				}

				_, err = dmgr.HttpDeviceManagerSDK.GetDeviceByDMS(ctx, services.GetDevicesByDMSInput{
					DMSID:     dms.ID,
					ListInput: request.ListInput,
				})

				if err != nil {
					t.Fatalf("could not retrieve a device: %s", err)
				}

				return devices, nil
			},
			resultCheck: func(devices []models.Device, err error) {
				check := 0
				devTest := devDMS1[:2]
				if len(devices) != 2 {
					t.Fatalf("the amount is two, got %d", len(devices))
				}
				for _, id := range devTest {
					contains := slices.ContainsFunc(devices, func(device models.Device) bool {
						return device.ID == id
					})
					if contains != true {
						t.Fatalf("the device id is not of this test")
					} else {
						check += 1
					}
				}
				if check != 2 {
					t.Fatalf("device with a different id")
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
					ID:        devDMS2[0],
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
					ID:        devDMS2[1],
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
					ID:        devDMS2[2],
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
				check := 0
				if len(devices) != 3 {
					t.Fatalf("the amount is three, got %d", len(devices))
				}
				for _, id := range devDMS2 {
					contains := slices.ContainsFunc(devices, func(device models.Device) bool {
						return device.ID == id
					})
					if contains != true {
						t.Fatalf("the device id is not of this test")
					} else {
						check += 1
					}
				}
				if check != 3 {
					t.Fatalf("device with a different id")
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

/*
func TestUpdateDeviceIdentitySlot(t *testing.T) {

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

	var testcases = []struct {
		name        string
		run         func() (*models.Device, error)
		resultCheck func(devices *models.Device, err error)
	}{
		{
			name: "OK/UpdateDeviceIdentity",
			run: func() (*models.Device, error) {

				device, err := dmgr.HttpDeviceManagerSDK.UpdateDeviceIdentitySlot(context.Background(), services.UpdateDeviceIdentitySlotInput{
					ID: "test",
					Slot: models.Slot[string]{
						ActiveVersion: 234,
					},
				})

				if err != nil {
					t.Fatalf("error while updating identity: %s", err)
				}

				return device, nil
			},
			resultCheck: func(device *models.Device, err error) {

				if err != nil {
					t.Fatalf("got an unexepected error: %s", err)
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
*/
func TestDecommissionDevice(t *testing.T) {
	devDMS1 := [3]string{"test1", "test2", "test3"}

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

		return dmsMgr.HttpDeviceManagerSDK.CreateDMS(context.Background(), input)

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
					ID:        devDMS1[0],
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
					ID:        devDMS1[1],
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
				check := 0
				devTest := devDMS1[:2]
				if len(devices) != 2 {
					t.Fatalf("the amount is two, got %d", len(devices))
				}
				for _, id := range devTest {
					contains := slices.ContainsFunc(devices, func(device models.Device) bool {
						return device.ID == id
					})
					if contains != true {
						t.Fatalf("the device id is not of this test")
					} else {
						check += 1
					}
				}
				if check != 2 {
					t.Fatalf("device with a different id")
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
		t.Fatalf("expected 2 devices, got %d", len(devices))
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
		t.Fatalf("expected 2 more devices, got %d", len(devices))
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

	bookmark, err = dmgr.HttpDeviceManagerSDK.GetDevices(ctx, request)
	if err != nil {
		t.Fatalf("could not retrieve device: %s", err)
	}

	if len(devices) != 1 {
		t.Fatalf("could not retrieve device: %v", len(devices))
	}
	checkDevice(t, &devices[0], deviceSample5)

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
		ID: deviceSample.ID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), map[string]interface{}{"test": "test2"}).
			Build(),
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
