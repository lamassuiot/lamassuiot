package devicemanager

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestCreateDeviceGroup(t *testing.T) {
	ctx := context.Background()
	dmgr, _, err := StartDeviceManagerServiceTestServer(t, false, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	// Use HTTP SDK to test through HTTP layer
	client := dmgr.HttpDeviceManagerSDK

	testCases := []struct {
		name        string
		input       services.CreateDeviceGroupInput
		expectError bool
		errorCheck  func(error) bool
	}{
		{
			name: "OK/CreateRootGroup",
			input: services.CreateDeviceGroupInput{
				ID:          uuid.NewString(),
				Name:        "Test Root Group",
				Description: "A test root group",
				ParentID:    nil,
				Criteria: []models.DeviceGroupFilterOption{
					{
						Field:           "tags",
						FilterOperation: int(resources.StringArrayContains),
						Value:           "production",
					},
				},
			},
			expectError: false,
		},
		{
			name: "Err/InvalidFilterField",
			input: services.CreateDeviceGroupInput{
				ID:          uuid.NewString(),
				Name:        "Invalid Filter Group",
				Description: "Group with invalid filter field",
				ParentID:    nil,
				Criteria: []models.DeviceGroupFilterOption{
					{
						Field:           "invalid_field",
						FilterOperation: int(resources.StringEqual),
						Value:           "test",
					},
				},
			},
			expectError: true,
			errorCheck: func(err error) bool {
				// When testing through HTTP SDK, error messages may be more specific
				// Check if error message contains indication of invalid filter field
				return err != nil && (errors.Is(err, errs.ErrValidateBadRequest) ||
					strings.Contains(err.Error(), "invalid filter field"))
			},
		},
		{
			name: "Err/CircularReferenceToSelf",
			input: services.CreateDeviceGroupInput{
				ID:          uuid.NewString(),
				Name:        "Self Reference Group",
				Description: "Group referencing itself",
				ParentID:    stringPtr(""), // Will be set to ID below
				Criteria:    []models.DeviceGroupFilterOption{},
			},
			expectError: true,
			errorCheck: func(err error) bool {
				return errors.Is(err, errs.ErrDeviceGroupCircularReference)
			},
		},
		{
			name: "Err/ParentNotFound",
			input: services.CreateDeviceGroupInput{
				ID:          uuid.NewString(),
				Name:        "Orphan Group",
				Description: "Group with non-existent parent",
				ParentID:    stringPtr(uuid.NewString()), // Use valid UUID for non-existent parent
				Criteria:    []models.DeviceGroupFilterOption{},
			},
			expectError: true,
			errorCheck: func(err error) bool {
				return errors.Is(err, errs.ErrDeviceGroupNotFound)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Special case: set ParentID to ID for circular reference test
			if tc.name == "Err/CircularReferenceToSelf" {
				tc.input.ParentID = &tc.input.ID
			}

			group, err := client.CreateDeviceGroup(ctx, tc.input)

			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				if tc.errorCheck != nil && !tc.errorCheck(err) {
					t.Fatalf("error check failed: got %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				if group.ID != tc.input.ID {
					t.Errorf("expected ID %s, got %s", tc.input.ID, group.ID)
				}
				if group.Name != tc.input.Name {
					t.Errorf("expected Name %s, got %s", tc.input.Name, group.Name)
				}
			}
		})
	}
}

func TestNestedDeviceGroups(t *testing.T) {
	ctx := context.Background()
	dmgr, _, err := StartDeviceManagerServiceTestServer(t, false, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	// Use HTTP SDK to test through HTTP layer
	client := dmgr.HttpDeviceManagerSDK

	// Create root group
	rootGroupID := uuid.NewString()
	_, err = client.CreateDeviceGroup(ctx, services.CreateDeviceGroupInput{
		ID:          rootGroupID,
		Name:        "All Sensors",
		Description: "Root group for all sensors",
		ParentID:    nil,
		Criteria: []models.DeviceGroupFilterOption{
			{
				Field:           "tags",
				FilterOperation: int(resources.StringArrayContains),
				Value:           "sensor",
			},
		},
	})
	if err != nil {
		t.Fatalf("could not create root group: %s", err)
	}

	// Create child group
	childGroupID := uuid.NewString()
	childGroup, err := client.CreateDeviceGroup(ctx, services.CreateDeviceGroupInput{
		ID:          childGroupID,
		Name:        "Active Sensors",
		Description: "Child group for active sensors",
		ParentID:    &rootGroupID,
		Criteria: []models.DeviceGroupFilterOption{
			{
				Field:           "status",
				FilterOperation: int(resources.EnumEqual),
				Value:           string(models.DeviceActive),
			},
		},
	})
	if err != nil {
		t.Fatalf("could not create child group: %s", err)
	}

	// Verify parent relationship
	if childGroup.ParentID == nil || *childGroup.ParentID != rootGroupID {
		t.Errorf("expected parent ID %s, got %v", rootGroupID, childGroup.ParentID)
	}

	// Create grandchild group
	grandchildGroupID := uuid.NewString()
	grandchildGroup, err := client.CreateDeviceGroup(ctx, services.CreateDeviceGroupInput{
		ID:          grandchildGroupID,
		Name:        "High Temp Active Sensors",
		Description: "Grandchild group for high temp active sensors",
		ParentID:    &childGroupID,
		Criteria: []models.DeviceGroupFilterOption{
			{
				Field:           "metadata",
				FilterOperation: int(resources.JsonPathExpression),
				Value:           "[temp] > 50",
			},
		},
	})
	if err != nil {
		t.Fatalf("could not create grandchild group: %s", err)
	}

	// Test circular reference prevention
	// Try to make root group a child of grandchild (should fail)
	_, err = client.UpdateDeviceGroup(ctx, services.UpdateDeviceGroupInput{
		ID:       rootGroupID,
		ParentID: &grandchildGroupID,
	})
	if err == nil {
		t.Fatal("expected circular reference error but got none")
	}
	if !errors.Is(err, errs.ErrDeviceGroupCircularReference) {
		t.Fatalf("expected ErrDeviceGroupCircularReference, got %v", err)
	}

	// Verify grandchild has correct parent
	if grandchildGroup.ParentID == nil || *grandchildGroup.ParentID != childGroupID {
		t.Errorf("expected parent ID %s, got %v", childGroupID, grandchildGroup.ParentID)
	}
}

func TestGetDevicesByGroup(t *testing.T) {
	ctx := context.Background()
	dmgr, _, err := StartDeviceManagerServiceTestServer(t, false, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	// Use HTTP SDK to test through HTTP layer
	client := dmgr.HttpDeviceManagerSDK

	// Create test devices
	device1ID := uuid.NewString()
	_, err = client.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        device1ID,
		Tags:      []string{"sensor", "production"},
		DMSID:     "test-dms",
		Icon:      "sensor",
		IconColor: "#00FF00",
	})
	if err != nil {
		t.Fatalf("could not create device 1: %s", err)
	}

	device2ID := uuid.NewString()
	_, err = client.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        device2ID,
		Tags:      []string{"sensor", "development"},
		DMSID:     "test-dms",
		Icon:      "sensor",
		IconColor: "#0000FF",
	})
	if err != nil {
		t.Fatalf("could not create device 2: %s", err)
	}

	device3ID := uuid.NewString()
	_, err = client.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        device3ID,
		Tags:      []string{"actuator", "production"},
		DMSID:     "test-dms",
		Icon:      "actuator",
		IconColor: "#FF0000",
	})
	if err != nil {
		t.Fatalf("could not create device 3: %s", err)
	}

	// Create device group for sensors
	sensorGroupID := uuid.NewString()
	_, err = dmgr.Service.CreateDeviceGroup(ctx, services.CreateDeviceGroupInput{
		ID:          sensorGroupID,
		Name:        "Sensor Devices",
		Description: "All sensor devices",
		ParentID:    nil,
		Criteria: []models.DeviceGroupFilterOption{
			{
				Field:           "tags",
				FilterOperation: int(resources.StringArrayContains),
				Value:           "sensor",
			},
		},
	})
	if err != nil {
		t.Fatalf("could not create sensor group: %s", err)
	}

	// Create nested group for production sensors
	prodSensorGroupID := uuid.NewString()
	_, err = client.CreateDeviceGroup(ctx, services.CreateDeviceGroupInput{
		ID:          prodSensorGroupID,
		Name:        "Production Sensors",
		Description: "Production sensor devices",
		ParentID:    &sensorGroupID,
		Criteria: []models.DeviceGroupFilterOption{
			{
				Field:           "tags",
				FilterOperation: int(resources.StringArrayContains),
				Value:           "production",
			},
		},
	})
	if err != nil {
		t.Fatalf("could not create production sensor group: %s", err)
	}

	// Test getting devices from root group (should return 2 sensors)
	sensorDevices := []models.Device{}
	_, err = client.GetDevicesByGroup(ctx, services.GetDevicesByGroupInput{
		GroupID: sensorGroupID,
		ListInput: resources.ListInput[models.Device]{
			ExhaustiveRun: false,
			ApplyFunc: func(dev models.Device) {
				sensorDevices = append(sensorDevices, dev)
			},
		},
	})
	if err != nil {
		t.Fatalf("could not get devices by sensor group: %s", err)
	}
	if len(sensorDevices) != 2 {
		t.Errorf("expected 2 sensor devices, got %d", len(sensorDevices))
	}

	// Test getting devices from nested group (should return 1 production sensor)
	prodSensorDevices := []models.Device{}
	_, err = client.GetDevicesByGroup(ctx, services.GetDevicesByGroupInput{
		GroupID: prodSensorGroupID,
		ListInput: resources.ListInput[models.Device]{
			ExhaustiveRun: false,
			ApplyFunc: func(dev models.Device) {
				prodSensorDevices = append(prodSensorDevices, dev)
			},
		},
	})
	if err != nil {
		t.Fatalf("could not get devices by production sensor group: %s", err)
	}
	if len(prodSensorDevices) != 1 {
		t.Errorf("expected 1 production sensor device, got %d", len(prodSensorDevices))
	}
	if len(prodSensorDevices) > 0 && prodSensorDevices[0].ID != device1ID {
		t.Errorf("expected device1 in production sensors, got %s", prodSensorDevices[0].ID)
	}
}

func TestGetDeviceGroupStats(t *testing.T) {
	ctx := context.Background()
	dmgr, testServer, err := StartDeviceManagerServiceTestServer(t, false, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	// Use HTTP SDK to test through HTTP layer
	client := dmgr.HttpDeviceManagerSDK

	// Create test devices with different statuses
	device1ID := uuid.NewString()
	_, err = client.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        device1ID,
		Tags:      []string{"sensor"},
		DMSID:     "test-dms",
		Icon:      "sensor",
		IconColor: "#00FF00",
	})
	if err != nil {
		t.Fatalf("could not create device 1: %s", err)
	}

	device2ID := uuid.NewString()
	_, err = client.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        device2ID,
		Tags:      []string{"sensor"},
		DMSID:     "test-dms",
		Icon:      "sensor",
		IconColor: "#0000FF",
	})
	if err != nil {
		t.Fatalf("could not create device 2: %s", err)
	}

	device3ID := uuid.NewString()
	_, err = client.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        device3ID,
		Tags:      []string{"actuator"},
		DMSID:     "test-dms",
		Icon:      "actuator",
		IconColor: "#FF0000",
	})
	if err != nil {
		t.Fatalf("could not create device 3: %s", err)
	}

	// Create device group for sensors
	sensorGroupID := uuid.NewString()
	_, err = client.CreateDeviceGroup(ctx, services.CreateDeviceGroupInput{
		ID:          sensorGroupID,
		Name:        "Sensor Devices",
		Description: "All sensor devices",
		ParentID:    nil,
		Criteria: []models.DeviceGroupFilterOption{
			{
				Field:           "tags",
				FilterOperation: int(resources.StringArrayContains),
				Value:           "sensor",
			},
		},
	})
	if err != nil {
		t.Fatalf("could not create sensor group: %s", err)
	}

	// Get stats for sensor group
	stats, err := client.GetDeviceGroupStats(ctx, services.GetDeviceGroupStatsInput{
		GroupID: sensorGroupID,
	})
	if err != nil {
		t.Fatalf("could not get device group stats: %s", err)
	}

	// Verify total count
	if stats.TotalDevices != 2 {
		t.Errorf("expected 2 total devices, got %d", stats.TotalDevices)
	}

	// Verify status distribution
	if stats.DevicesStatus[models.DeviceNoIdentity] != 2 {
		t.Errorf("expected 2 devices with NO_IDENTITY status, got %d", stats.DevicesStatus[models.DeviceNoIdentity])
	}

	// Test non-existent group
	_, err = client.GetDeviceGroupStats(ctx, services.GetDeviceGroupStatsInput{
		GroupID: uuid.NewString(), // Use valid UUID for non-existent group
	})
	if err == nil {
		t.Fatal("expected error for non-existent group but got none")
	}
	if !errors.Is(err, errs.ErrDeviceGroupNotFound) {
		t.Fatalf("expected ErrDeviceGroupNotFound, got %v", err)
	}

	// Clean up
	testServer.AfterSuite()
}

func TestUpdateDeviceGroup(t *testing.T) {
	ctx := context.Background()
	dmgr, _, err := StartDeviceManagerServiceTestServer(t, false, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	// Use HTTP SDK to test through HTTP layer
	client := dmgr.HttpDeviceManagerSDK

	// Create initial group
	groupID := uuid.NewString()
	_, err = client.CreateDeviceGroup(ctx, services.CreateDeviceGroupInput{
		ID:          groupID,
		Name:        "Original Name",
		Description: "Original Description",
		ParentID:    nil,
		Criteria: []models.DeviceGroupFilterOption{
			{
				Field:           "tags",
				FilterOperation: int(resources.StringArrayContains),
				Value:           "original",
			},
		},
	})
	if err != nil {
		t.Fatalf("could not create group: %s", err)
	}

	// Update group
	updatedGroup, err := client.UpdateDeviceGroup(ctx, services.UpdateDeviceGroupInput{
		ID:          groupID,
		Name:        "Updated Name",
		Description: "Updated Description",
		Criteria: []models.DeviceGroupFilterOption{
			{
				Field:           "tags",
				FilterOperation: int(resources.StringArrayContains),
				Value:           "updated",
			},
		},
	})
	if err != nil {
		t.Fatalf("could not update group: %s", err)
	}

	if updatedGroup.Name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got %s", updatedGroup.Name)
	}
	if updatedGroup.Description != "Updated Description" {
		t.Errorf("expected description 'Updated Description', got %s", updatedGroup.Description)
	}
}

func TestDeleteDeviceGroup(t *testing.T) {
	ctx := context.Background()
	dmgr, _, err := StartDeviceManagerServiceTestServer(t, false, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	// Use HTTP SDK to test through HTTP layer
	client := dmgr.HttpDeviceManagerSDK

	// Create group
	groupID := uuid.NewString()
	_, err = client.CreateDeviceGroup(ctx, services.CreateDeviceGroupInput{
		ID:          groupID,
		Name:        "Test Group",
		Description: "Group to be deleted",
		ParentID:    nil,
		Criteria:    []models.DeviceGroupFilterOption{},
	})
	if err != nil {
		t.Fatalf("could not create group: %s", err)
	}

	// Delete group
	err = client.DeleteDeviceGroup(ctx, services.DeleteDeviceGroupInput{
		ID: groupID,
	})
	if err != nil {
		t.Fatalf("could not delete group: %s", err)
	}

	// Verify group is deleted
	_, err = client.GetDeviceGroupByID(ctx, services.GetDeviceGroupByIDInput{
		ID: groupID,
	})
	if err == nil {
		t.Fatal("expected error when getting deleted group but got none")
	}
	if !errors.Is(err, errs.ErrDeviceGroupNotFound) {
		t.Fatalf("expected ErrDeviceGroupNotFound, got %v", err)
	}
}

func TestGetDeviceGroups(t *testing.T) {
	ctx := context.Background()
	dmgr, _, err := StartDeviceManagerServiceTestServer(t, false, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	// Use HTTP SDK to test through HTTP layer
	client := dmgr.HttpDeviceManagerSDK

	// Create multiple groups
	group1ID := uuid.NewString()
	_, err = client.CreateDeviceGroup(ctx, services.CreateDeviceGroupInput{
		ID:          group1ID,
		Name:        "Group 1",
		Description: "First group",
		ParentID:    nil,
		Criteria:    []models.DeviceGroupFilterOption{},
	})
	if err != nil {
		t.Fatalf("could not create group 1: %s", err)
	}

	group2ID := uuid.NewString()
	_, err = client.CreateDeviceGroup(ctx, services.CreateDeviceGroupInput{
		ID:          group2ID,
		Name:        "Group 2",
		Description: "Second group",
		ParentID:    nil,
		Criteria:    []models.DeviceGroupFilterOption{},
	})
	if err != nil {
		t.Fatalf("could not create group 2: %s", err)
	}

	// Get all groups
	groups := []models.DeviceGroup{}
	_, err = client.GetDeviceGroups(ctx, services.GetDeviceGroupsInput{
		ListInput: resources.ListInput[models.DeviceGroup]{
			ExhaustiveRun: false,
			ApplyFunc: func(group models.DeviceGroup) {
				groups = append(groups, group)
			},
		},
	})
	if err != nil {
		t.Fatalf("could not get device groups: %s", err)
	}

	if len(groups) < 2 {
		t.Errorf("expected at least 2 groups, got %d", len(groups))
	}
}

// Helper function
func stringPtr(s string) *string {
	return &s
}
