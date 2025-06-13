package assemblers

import (
	"context"
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestGetKeys(t *testing.T) {

	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithService(KMS).Build(t)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	kmsTest := serverTest.KMS

	var testcases = []struct {
		name        string
		run         func(kmsSDK services.KMSService) ([]*models.KeyInfo, error)
		resultCheck func(result []*models.KeyInfo, err error) error
	}{
		{
			name: "OK/HelloWorldMessage",
			run: func(kmsSDK services.KMSService) ([]*models.KeyInfo, error) {
				return kmsSDK.GetKeys(context.Background())
			},
			resultCheck: func(result []*models.KeyInfo, err error) error {
				if err != nil {
					return fmt.Errorf("should've launch GetHelloWorld without error, but got error: %s", err)
				}

				/*if result == nil || *result != "Hello World!" {
					return fmt.Errorf("should've got 'Hello World!' but got: %v", *result)
				}*/

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			err = tc.resultCheck(kmsTest.Service.GetKeys(context.Background()))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}

}
