package main

import (
	lamassu "github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

var (
	version   string = "v0"    // api version
	sha1ver   string = "-"     // sha1 revision used to build the program
	buildTime string = "devTS" // when the executable was built
)

func main() {
	lamassu.RunCA(models.APIServiceInfo{
		Version:   version,
		BuildSHA:  sha1ver,
		BuildTime: buildTime,
	})
}
