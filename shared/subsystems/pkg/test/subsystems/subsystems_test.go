package subsystems

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockPostgresSubsystem struct{}

func (m *MockPostgresSubsystem) Run(bool) (*SubsystemBackend, error) {
	return &SubsystemBackend{}, nil
}

func TestRegisterAndRetrievePostgresSubsystem(t *testing.T) {
	// Create a mock Postgres subsystem
	mockPostgres := &MockPostgresSubsystem{}

	// Register the mock Postgres subsystem
	RegisterSubsystemBuilder(Postgres, mockPostgres)

	// Retrieve the registered Postgres subsystem
	retrievedSubsystem := GetSubsystemBuilder[Subsystem](Postgres)

	// Verify that the retrieved subsystem is the same as the registered one
	require.NotNil(t, retrievedSubsystem)
	assert.Equal(t, mockPostgres, retrievedSubsystem)
}

func TestPostgresSubsystemRun(t *testing.T) {
	// Create a mock Postgres subsystem
	mockPostgres := &MockPostgresSubsystem{}

	// Register the mock Postgres subsystem
	RegisterSubsystemBuilder(Postgres, mockPostgres)

	// Retrieve the registered Postgres subsystem
	retrievedSubsystem := GetSubsystemBuilder[Subsystem](Postgres)

	// Run the retrieved subsystem
	backend, err := retrievedSubsystem.Run(true)

	// Verify the result
	require.NoError(t, err)
	require.NotNil(t, backend)
}
