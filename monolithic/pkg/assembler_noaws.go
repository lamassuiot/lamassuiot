//go:build noaws
// +build noaws

package pkg

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func AssembleAWSIoT(conf MonolithicConfig, caSDKBuilder func(serviceID string, src string) services.CAService, dmsMngrSDKBuilder func(serviceID string, src string) services.DMSManagerService, deviceMngrSDKBuilder func(serviceID string, src string) services.DeviceManagerService) error {
	return fmt.Errorf("AWS IoT is not supported in this build")
}
