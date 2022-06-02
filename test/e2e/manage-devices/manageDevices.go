package devices

import (
	"context"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
	filterTypes "github.com/lamassuiot/lamassuiot/pkg/utils/server/filters/types"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"
)

func ManageDevices(scaleIndex int, certPath string, domain string) error {
	var logger log.Logger
	logger = log.NewJSONLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	devClient, err := client.LamassuDevClient(certPath, domain)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}

	devices, _, err := devClient.GetDevices(context.Background(), filters.QueryParameters{Filters: []filterTypes.Filter{}, Sort: filters.SortOptions{SortMode: "DESC", SortField: "id"}, Pagination: filters.PaginationOptions{Limit: 10, Offset: 0}})
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	_, err = devClient.GetDeviceById(context.Background(), devices[0].Id)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	_, err = devClient.GetDeviceCertHistory(context.Background(), devices[0].Id)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	_, err = devClient.GetDeviceLogs(context.Background(), devices[0].Id)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}

	_, err = devClient.GetDeviceCert(context.Background(), devices[0].Id)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	return nil
}
