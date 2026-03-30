package authz

import (
	"testing"
)

func TestAuthorizationGraph_Build(t *testing.T) {
	schemas := NewSchemaRegistry()
	if err := schemas.Load("../../examples/iot/schemas.tests.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policies := NewPolicyRegistry()
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	graph := NewAuthorizationGraph()
	if err := graph.BuildFromPoliciesAndSchemas(policies, schemas); err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	// Verify nodes exist
	if graph.GetNode("public.organization") == nil {
		t.Error("Organization node not found")
	}
	if graph.GetNode("public.building") == nil {
		t.Error("Building node not found")
	}
	if graph.GetNode("public.gateway") == nil {
		t.Error("Gateway node not found")
	}
	if graph.GetNode("public.device") == nil {
		t.Error("Device node not found")
	}
	if graph.GetNode("public.user") == nil {
		t.Error("User node not found")
	}
}

func TestAuthorizationGraph_FindPathsToUser(t *testing.T) {
	schemas := NewSchemaRegistry()
	if err := schemas.Load("../../examples/iot/schemas.tests.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policies := NewPolicyRegistry()
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	graph := NewAuthorizationGraph()
	if err := graph.BuildFromPoliciesAndSchemas(policies, schemas); err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	// Find paths from device to user
	paths := graph.FindPathsToUser("public.device", "read", 10)

	if len(paths) == 0 {
		t.Error("Expected at least one path from device to user")
	}

	t.Logf("Total paths from device to user: %d", len(paths))

	// Log the paths found
	for i, path := range paths {
		t.Logf("Path %d (%d hops):", i, len(path))
		for j, edge := range path {
			t.Logf("  Hop %d: %s -[%s]-> %s", j, edge.From, edge.Via, edge.To)
		}
	}
}

func TestAuthorizationGraph_FindPathsBetween(t *testing.T) {
	schemas := NewSchemaRegistry()
	if err := schemas.Load("../../examples/iot/schemas.tests.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policies := NewPolicyRegistry()
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	graph := NewAuthorizationGraph()
	if err := graph.BuildFromPoliciesAndSchemas(policies, schemas); err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	// Find paths from organization to device
	paths := graph.FindPathsBetween("public.organization", "public.device", "read", 10)

	if len(paths) == 0 {
		t.Error("Expected at least one path from organization to device")
	}

	// Should find path: organization -> building -> gateway -> device
	for _, path := range paths {
		t.Logf("Path with %d edges:", len(path))
		for i, edge := range path {
			t.Logf("  Edge %d: %s -[%s]-> %s", i, edge.From, edge.Via, edge.To)
		}
	}

	// Verify we have the expected 3-hop path
	foundThreeHopPath := false
	for _, path := range paths {
		if len(path) == 3 &&
			path[0].From == "public.organization" && path[0].To == "public.building" &&
			path[1].From == "public.building" && path[1].To == "public.gateway" &&
			path[2].From == "public.gateway" && path[2].To == "public.device" {
			foundThreeHopPath = true
		}
	}

	if !foundThreeHopPath {
		t.Error("Expected to find 3-hop path: organization -> building -> gateway -> device")
	}
}

func TestAuthorizationGraph_BuildingToDevice(t *testing.T) {
	schemas := NewSchemaRegistry()
	if err := schemas.Load("../../examples/iot/schemas.tests.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policies := NewPolicyRegistry()
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	graph := NewAuthorizationGraph()
	if err := graph.BuildFromPoliciesAndSchemas(policies, schemas); err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	// Find paths from building to device
	paths := graph.FindPathsBetween("public.building", "public.device", "read", 10)

	if len(paths) == 0 {
		t.Error("Expected at least one path from building to device")
	}

	// Should find path: building -> gateway -> device
	foundTwoHopPath := false
	for _, path := range paths {
		if len(path) == 2 &&
			path[0].From == "public.building" && path[0].To == "public.gateway" &&
			path[1].From == "public.gateway" && path[1].To == "public.device" {
			foundTwoHopPath = true
			t.Logf("Found 2-hop path: building -[%s]-> gateway -[%s]-> device",
				path[0].Via, path[1].Via)
		}
	}

	if !foundTwoHopPath {
		t.Error("Expected to find 2-hop path: building -> gateway -> device")
	}
}

func TestAuthorizationGraph_NoPath(t *testing.T) {
	schemas := NewSchemaRegistry()
	if err := schemas.Load("../../examples/iot/schemas.tests.json", "iot"); err != nil {
		t.Fatalf("Failed to load schemas: %v", err)
	}

	policies := NewPolicyRegistry()
	if err := policies.Load("../../examples/iot/policies.json"); err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	graph := NewAuthorizationGraph()
	if err := graph.BuildFromPoliciesAndSchemas(policies, schemas); err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	// Try to find path from device to organization (should be none - uni-directional)
	paths := graph.FindPathsBetween("public.device", "public.organization", "read", 10)

	if len(paths) > 0 {
		t.Errorf("Expected no paths from device to organization (uni-directional), but found %d", len(paths))
		for _, path := range paths {
			t.Logf("Unexpected path:")
			for i, edge := range path {
				t.Logf("  Edge %d: %s -[%s]-> %s", i, edge.From, edge.Via, edge.To)
			}
		}
	}
}
