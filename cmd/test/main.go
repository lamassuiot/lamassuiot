package main

import (
	"context"
	"fmt"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	devicesRepo "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository/postgres"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

func main() {
	var logger log.Logger

	logger = log.NewNopLogger()
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	dsn := "host=localhost user=admin password=admin dbname=postgres port=5435 sslmode=disable"
	dialector := postgres.Open(dsn)
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Info),
	})
	if err != nil {
		panic(err)
	}

	devicesRepository := devicesRepo.NewDevicesPostgresDB(db, logger)

	id := goid.NewV4UUID().String()
	svc := service.NewDeviceManagerService(logger, devicesRepository, nil, nil, nil)
	out, err := svc.CreateDevice(context.Background(), &api.CreateDeviceInput{
		DeviceID:    id,
		Alias:       "test",
		Tags:        []string{"testTag"},
		IconColor:   "red",
		IconName:    "testIcon",
		Description: "desc",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(out)

	outSlot, err := svc.AddDeviceSlot(context.Background(), &api.AddDeviceSlotInput{
		DeviceID:          id,
		SlotID:            "Slot1",
		ActiveCertificate: &api.Certificate{},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(outSlot)

	outGetDevice, err := svc.GetDeviceById(context.Background(), &api.GetDeviceByIdInput{
		ID: id,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(outGetDevice)
	fmt.Println(outGetDevice.Slots[0].ArchiveCertificates)

}
