package cmp

import (
	"testing"

	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogCMPFailure(t *testing.T) {
	t.Run("rejection is logged as warning", func(t *testing.T) {
		logger, hook := logrustest.NewNullLogger()
		routes := &cmpHttpRoutes{logger: logrus.NewEntry(logger)}

		routes.logCMPFailure(
			&corecmp.RequestPKIHeader{TransactionID: []byte{0x01, 0x02}},
			corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"request is not authorized",
			"dms-1",
			corecmp.PKIFailureInfoNotAuthorized,
		)

		entry := hook.LastEntry()
		require.NotNil(t, entry)
		assert.Equal(t, logrus.WarnLevel, entry.Level)
		assert.Equal(t, "CMP operation rejected", entry.Message)
		assert.Equal(t, "rejection", entry.Data["pkiStatus"])
		assert.Equal(t, []string{"notAuthorized"}, entry.Data["pkiFailureInfo"])
		assert.Equal(t, "dms-1", entry.Data["dms"])
		assert.Equal(t, "0102", entry.Data["txid"])
		assert.Equal(t, "request is not authorized", entry.Data["reason"])
	})

	t.Run("systemFailure is logged as error", func(t *testing.T) {
		logger, hook := logrustest.NewNullLogger()
		routes := &cmpHttpRoutes{logger: logrus.NewEntry(logger)}

		routes.logCMPFailure(
			nil,
			corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"internal error",
			"dms-2",
			corecmp.PKIFailureInfoSystemFailure,
		)

		entry := hook.LastEntry()
		require.NotNil(t, entry)
		assert.Equal(t, logrus.ErrorLevel, entry.Level)
		assert.Equal(t, "rejection", entry.Data["pkiStatus"])
		assert.Equal(t, []string{"systemFailure"}, entry.Data["pkiFailureInfo"])
	})

	t.Run("non-failure status is not logged", func(t *testing.T) {
		logger, hook := logrustest.NewNullLogger()
		routes := &cmpHttpRoutes{logger: logrus.NewEntry(logger)}

		routes.logCMPFailure(nil, corecmp.PKIStatus(corecmp.PKIStatusAccepted), "", "dms-3")

		assert.Nil(t, hook.LastEntry())
	})
}
