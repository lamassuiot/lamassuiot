package dmss

import (
	"context"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/jakehl/goid"
	dmsDTO "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
	filterTypes "github.com/lamassuiot/lamassuiot/pkg/utils/server/filters/types"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"
)

func ManageDMSs(dmsNumber int, dmsid string, caName string, scaleIndex int, certPath string, domain string) error {
	var logger log.Logger
	logger = log.NewJSONLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	dmsClient, err := client.LamassuDmsClient(certPath, domain)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	devClient, err := client.LamassuDevClient(certPath, domain)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	var dms dmsDTO.DMS
	dmsName := goid.NewV4UUID().String()
	_, dms, err = dmsClient.CreateDMSForm(context.Background(), dmsDTO.Subject{CN: dmsName}, dmsDTO.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dmsName)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}

	dms, err = dmsClient.UpdateDMSStatus(context.Background(), "APPROVED", dms.Id, []string{caName})
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	_, err = dmsClient.GetDMSs(context.Background())
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	dms, err = dmsClient.UpdateDMSStatus(context.Background(), "REVOKED", dms.Id, nil)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	err = dmsClient.DeleteDMS(context.Background(), dms.Id)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	_, err = dmsClient.GetDMSbyID(context.Background(), dmsid)
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	_, err = devClient.GetDmsCertHistoryThirtyDays(context.Background(), filters.QueryParameters{Filters: []filterTypes.Filter{}, Sort: filters.SortOptions{SortMode: "DESC", SortField: "id"}, Pagination: filters.PaginationOptions{Limit: 10, Offset: 0}})
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	_, err = devClient.GetDmsLastIssuedCert(context.Background(), filters.QueryParameters{Filters: []filterTypes.Filter{}, Sort: filters.SortOptions{SortMode: "DESC", SortField: "dms_id"}, Pagination: filters.PaginationOptions{Limit: 10, Offset: 0}})
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	_, err = devClient.GetDevicesByDMS(context.Background(), dmsid, filters.QueryParameters{Filters: []filterTypes.Filter{}, Sort: filters.SortOptions{SortMode: "DESC", SortField: "dms_id"}, Pagination: filters.PaginationOptions{Limit: 10, Offset: 0}})
	if err != nil {
		level.Error(logger).Log("err", err)
		return err
	}
	return nil
}
