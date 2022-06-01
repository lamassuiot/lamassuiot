package certs

import (
	"context"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
	filterTypes "github.com/lamassuiot/lamassuiot/pkg/utils/server/filters/types"
	"github.com/lamassuiot/lamassuiot/test/e2e/utils"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"
)

var dmsCertFile = "./test/e2e/industrial-environment/dmsPer.crt"
var dmsKeyFile = "./test/e2e/industrial-environment/dmsPer.key"

func ManageCerts(caName string, scaleIndex int, certPath string, domain string) error {
	var logger log.Logger
	logger = log.NewJSONLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	caClient, err := client.LamassuCaClient(certPath, domain)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	devClient, err := client.LamassuDevClient(certPath, domain)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}

	serverCert, err := utils.ReadCertPool(certPath)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	dmsCert, err := utils.ReadCert(dmsCertFile)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	dmsKey, err := utils.ReadKey(dmsKeyFile)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	_, err = devClient.CACerts(context.Background(), caName, dmsCert, dmsKey, serverCert, domain+"/api/devmanager")
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}

	_, err = caClient.GetIssuedCerts(context.Background(), caDTO.Pki, caName, filters.QueryParameters{Filters: []filterTypes.Filter{}, Sort: filters.SortOptions{SortMode: "DESC", SortField: "id"}, Pagination: filters.PaginationOptions{Limit: 10, Offset: 0}})
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	return nil
}
