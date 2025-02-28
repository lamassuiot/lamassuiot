package assemblers

import (
	"fmt"
	"testing"
)

func StartKMSTestServer(t *testing.T, withEventBus bool) (*DeviceManagerTestServer, error) {
	builder := TestServiceBuilder{}.WithDatabase("kms").WithService(CA, DEVICE_MANAGER)
	if withEventBus {
		builder = builder.WithEventBus()
	}
	testServer, err := builder.Build(t)
	if err != nil {
		return nil, fmt.Errorf("could not create Device Manager test server: %s", err)
	}
	return testServer.DeviceManager, nil
}
