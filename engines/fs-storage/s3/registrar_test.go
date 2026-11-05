package s3

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	fsstorage "github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/fs-storage"
)

func TestRegisterS3(t *testing.T) {
	Register()

	if builder := fsstorage.GetEngineBuilder(config.AWSS3); builder == nil {
		t.Fatal("S3 filesystem engine was not registered")
	}
}
