package authz

import (
	"strings"
	"testing"
)

func TestFilterGenerator_ControlActionOnDevice(t *testing.T) {
	// Setup registries
	schemas := NewSchemaRegistry()
	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	// Load the specific policy from the user's policy file
	policies := NewPolicyRegistry()
	if err := policies.Load("../../examples/iot/test-policy-control.json"); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	fg := NewFilterGenerator(schemas, policies)

	// Test control action on device - should cascade from org-1
	result, err := fg.GenerateListFilter("control", "public", "device")
	if err != nil {
		t.Fatalf("GenerateListFilter failed: %v", err)
	}

	whereClause := strings.Join(result.Conditions, " OR ")

	t.Logf("Generated WHERE clause: %s", whereClause)
	t.Logf("Generated JOINs: %v", result.Joins)

	// Debug: check what paths are found
	paths := fg.graph.FindPathsBetween("public.organization", "public.device", "control", 10)
	t.Logf("Found %d paths from organization to device for 'control' action", len(paths))
	for i, path := range paths {
		t.Logf("Path %d:", i)
		for j, edge := range path {
			t.Logf("  Edge %d: %s -[%s (actions: %v)]-> %s", j, edge.From, edge.Via, edge.Actions, edge.To)
		}
	}

	if whereClause == "1 = 0" {
		t.Fatal("Expected filter to allow control access via cascading from org-1, got impossible condition")
	}

	// Should have JOINs for cascading access path: org -> building -> gateway -> device
	if len(result.Joins) == 0 {
		t.Error("Expected JOINs for cascading access through organization -> building -> gateway -> device")
	}

	// Should have org-1 in inlined SQL condition
	if !strings.Contains(whereClause, "'org-1'") {
		t.Errorf("Expected 'org-1' in inlined SQL for cascading access, got: %s", whereClause)
	}

	// Now test specific check for device-1
	checkResult, err := fg.GenerateCheckFilter("control", "public", "device", map[string]string{"device_id": "device-1"})
	if err != nil {
		t.Fatalf("GenerateCheckFilter failed: %v", err)
	}

	checkWhereClause := strings.Join(checkResult.Conditions, " OR ")

	if checkWhereClause == "1 = 0" {
		t.Fatal("Expected check filter to allow control access to device-1")
	}

	// Should contain inlined id condition
	if !strings.Contains(checkWhereClause, "device_id = 'device-1'") {
		t.Errorf("Expected device_id condition in check filter, got: %s", checkWhereClause)
	}

	t.Logf("✓ SUCCESS: Control action on device-1 is properly cascaded from org-1")
	t.Logf("Check WHERE clause: %s", checkWhereClause)
}
