package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/configs"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/stretchr/testify/assert"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/estserver"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/mocks"
	verify "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/utils"
	estEndpoint "github.com/lamassuiot/lamassuiot/pkg/est/server/api/endpoint"

	//devicesStore "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device/store"

	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	devicesDB "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device/store/db"
	"github.com/opentracing/opentracing-go"

	"github.com/gavv/httpexpect/v2"
)

func TestDeviceHandler(t *testing.T) {

	tt := []struct {
		name                  string
		serviceInitialization func(s *service.Service)
		testRestEndpoint      func(e *httpexpect.Expect)
		testEstRestEndpoint   func(e *httpexpect.Expect)
	}{

		//Device-manager tests
		{
			name: "GetHealth",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/health").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("healthy")
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "GetStats",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				tags := []string{"tag1", "tag2"}
				(*s).PostDevice(ctx, "alias", "deviceID", "DmsID", "description", tags, "Cg/CgSmartphoneChip", "#0068D1")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/stats").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("scan_date")
				obj.Object().Value("stats").Object().ContainsKey("pending_enrollment")
				obj.Object().Value("stats").Object().ContainsKey("provisioned")
				obj.Object().Value("stats").Object().ContainsKey("decommissioned")
				obj.Object().Value("stats").Object().ContainsKey("provisioned_devices")
				obj.Object().Value("stats").Object().ContainsKey("expired")
				obj.Object().Value("stats").Object().ContainsKey("revoked")
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "GetStats_NotExistingPath",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				e.GET("/v1/stats/a").
					Expect().
					Status(http.StatusNotFound)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "GetDeviceById",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				tags := []string{"tag1", "tag2"}
				(*s).PostDevice(ctx, "alias", "deviceID", "DmsID", "description", tags, "Cg/CgSmartphoneChip", "#0068D1")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/devices/1").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("id")
				obj.Object().ContainsKey("alias")
				obj.Object().ContainsKey("description")
				obj.Object().ContainsKey("tags")
				obj.Object().ContainsKey("icon_name")
				obj.Object().ContainsKey("icon_color")
				obj.Object().ContainsKey("status")
				obj.Object().ContainsKey("dms_id")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")
				obj.Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Object().Value("subject").Object().ContainsKey("common_name")
				obj.Object().Value("subject").Object().ContainsKey("organization")
				obj.Object().Value("subject").Object().ContainsKey("organization_unit")
				obj.Object().Value("subject").Object().ContainsKey("country")
				obj.Object().Value("subject").Object().ContainsKey("state")
				obj.Object().Value("subject").Object().ContainsKey("locality")
				obj.Object().ContainsKey("creation_timestamp")
				obj.Object().ContainsKey("modification_timestamp")
				obj.Object().ContainsKey("current_certificate")
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "GetDeviceById_Error",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				e.GET("/v1/devices/error").
					Expect().
					Status(http.StatusNotFound)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "GetDevicesByDMS",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				tags := []string{"tag1", "tag2"}
				(*s).PostDevice(ctx, "alias", "deviceID", "DmsID", "description", tags, "Cg/CgSmartphoneChip", "#0068D1")
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/devices/dms/DmsID").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("total_devices")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("id")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("alias")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("description")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("tags")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("icon_name")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("icon_color")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("status")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("dms_id")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("alias")
				obj.Object().Value("devices").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("devices").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Object().Value("devices").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("type")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("common_name")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("organization")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("organization_unit")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("country")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("state")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("locality")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("creation_timestamp")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("modification_timestamp")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("current_certificate")

			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "GetDevicesByDMS_NotExistingPath",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				e.GET("/v1/devices/dms/error/DmsID").
					Expect().
					Status(http.StatusNotFound)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "CreateDevice",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				var tags []string

				device := fmt.Sprintf(`{"id":"2","alias":"alias","description":"description","tags": %v, "icon_name": "Cg/CgSmartphoneChip", "icon_color":"#0068D1", "dms_id": "dms_id"}`, tags)

				obj := e.POST("/v1/devices").WithBytes([]byte(device)).
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("status")
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "CreateDevice_NotExistingPath",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				e.GET("/v1/devices/id/devices").
					Expect().
					Status(http.StatusNotFound)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "CreateDevice_ErrDeviceWithoutId",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				var tags []string
				device := fmt.Sprintf(`{"id":"error","alias":"alias","description":"description","tags": %v, "icon_name": "Cg/CgSmartphoneChip", "icon_color":"#0068D1", "dms_id": "dms_id"}`, tags)

				e.POST("/v1/devices").WithBytes([]byte(device)).
					Expect().
					Status(http.StatusNotFound)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},

		{
			name: "CreateDevice_ValidationError",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				device := `"badRequest":"1"}`

				e.POST("/v1/devices").WithBytes([]byte(device)).
					Expect().
					Status(http.StatusBadRequest)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "CreateDevice_ValidationError",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				device := `{"badRequest":"1"}`

				e.POST("/v1/devices").WithBytes([]byte(device)).
					Expect().
					Status(http.StatusBadRequest)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},

		{
			name: "GetDevicesLogs",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				tags := []string{"tag1", "tag2"}
				(*s).PostDevice(ctx, "alias", "deviceID", "DmsID", "description", tags, "Cg/CgSmartphoneChip", "#0068D1")
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/devices/1/logs").
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("total_logs")
				obj.Object().Value("logs").Array().Element(0).Object().ContainsKey("id")
				obj.Object().Value("logs").Array().Element(0).Object().ContainsKey("device_id")
				obj.Object().Value("logs").Array().Element(0).Object().ContainsKey("log_type")
				obj.Object().Value("logs").Array().Element(0).Object().ContainsKey("log_message")
				obj.Object().Value("logs").Array().Element(0).Object().ContainsKey("timestamp")
				obj.Object().Value("logs").Array().Element(0).Object().ContainsKey("log_description")

			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "GetDevicesLogs_NotExistingPath",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				tags := []string{"tag1", "tag2"}
				(*s).PostDevice(ctx, "alias", "deviceID", "DmsID", "description", tags, "Cg/CgSmartphoneChip", "#0068D1")
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				e.GET("/v1/devices/1/logs/logs").
					Expect().
					Status(http.StatusNotFound)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "GetDevicesLogs_ErrMissingDevID",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				e.GET("/v1/devices/errorGetDeviceLogs/logs").
					Expect().
					Status(http.StatusNotFound)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},

		{
			name: "Get Devices",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				tags := []string{"tag1", "tag2"}
				(*s).PostDevice(ctx, "alias", "deviceID", "DmsID", "description", tags, "Cg/CgSmartphoneChip", "#0068D1")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/devices").WithQuery("&filter", "{or(contains(id,1)}").WithQuery("s", "{DESC,id}").WithQuery("page", "{1,15}").
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("total_devices")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("id")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("alias")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("description")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("tags")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("icon_name")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("icon_color")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("status")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("dms_id")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("alias")
				obj.Object().Value("devices").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("devices").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Object().Value("devices").Array().Element(0).Object().Value("key_metadata").Object().ContainsKey("type")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("common_name")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("organization")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("organization_unit")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("country")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("state")
				obj.Object().Value("devices").Array().Element(0).Object().Value("subject").Object().ContainsKey("locality")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("creation_timestamp")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("modification_timestamp")
				obj.Object().Value("devices").Array().Element(0).Object().ContainsKey("current_certificate")
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "GetDevices_NotExistingPath",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				e.GET("/v1/devices/notExistingPath/notExistingPath/notExistingPath/notExistingPath").
					Expect().
					Status(http.StatusNotFound)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},

		{
			name: "UpdateDeviceById",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				tags := []string{"tag1", "tag2"}
				(*s).PostDevice(ctx, "alias", "deviceID", "DmsID", "description", tags, "Cg/CgSmartphoneChip", "#0068D1")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				var tags []string
				device := fmt.Sprintf(`{"id":"1","alias":"update","description":"description","tags": %v, "icon_name": "Cg/CgSmartphoneChip", "icon_color":"#0068D1", "dms_id": "dms_id"}`, tags)

				obj := e.PUT("/v1/devices/deviceID").WithBytes([]byte(device)).
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("id")
				obj.Object().ContainsKey("alias")
				obj.Object().ContainsKey("description")
				obj.Object().ContainsKey("tags")
				obj.Object().ContainsKey("icon_name")
				obj.Object().ContainsKey("icon_color")
				obj.Object().ContainsKey("status")
				obj.Object().ContainsKey("dms_id")
				obj.Object().Value("key_metadata").Object().ContainsKey("bits")
				obj.Object().Value("key_metadata").Object().ContainsKey("strength")
				obj.Object().Value("key_metadata").Object().ContainsKey("type")
				obj.Object().Value("subject").Object().ContainsKey("common_name")
				obj.Object().Value("subject").Object().ContainsKey("organization")
				obj.Object().Value("subject").Object().ContainsKey("organization_unit")
				obj.Object().Value("subject").Object().ContainsKey("country")
				obj.Object().Value("subject").Object().ContainsKey("state")
				obj.Object().Value("subject").Object().ContainsKey("locality")
				obj.Object().ContainsKey("creation_timestamp")
				obj.Object().ContainsKey("modification_timestamp")
				obj.Object().ContainsKey("current_certificate")
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "UpdateDevice_NotExistingPath",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				e.PUT("/v1/devices/a/a").
					Expect().
					Status(http.StatusNotFound)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "UpdateDevice_JSONError",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				device := `"badRequest":"1"}`

				e.PUT("/v1/devices/deviceID").WithBytes([]byte(device)).
					Expect().
					Status(http.StatusBadRequest)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "UpdateDevice_NotExistingDeviceId",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				var tags []string

				device := fmt.Sprintf(`{"id":"3","alias":"alias","description":"description","tags": %v, "icon_name": "Cg/CgSmartphoneChip", "icon_color":"#0068D1", "dms_id": "dms_id"}`, tags)

				e.PUT("/v1/devices/error").WithBytes([]byte(device)).
					Expect().
					Status(http.StatusNotFound)

			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "UpdateDevice_ValidationError",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				device := `{"badRequest":"1"}`

				e.PUT("/v1/devices/1").WithBytes([]byte(device)).
					Expect().
					Status(http.StatusBadRequest)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "DeleteDevice_NotExistingDeviceId",
			serviceInitialization: func(s *service.Service) {

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				e.DELETE("/v1/devices/errorUpdateStatus").
					Expect().
					Status(http.StatusNotFound)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "DeleteDevice",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				tags := []string{"tag1", "tag2"}
				(*s).PostDevice(ctx, "alias", "deviceID", "DmsID", "description", tags, "Cg/CgSmartphoneChip", "#0068D1")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.DELETE("/v1/devices/1").
					Expect().
					Status(http.StatusOK).JSON()

				assert.Equal(t, "OK", obj.Raw().(string))
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},

		{
			name: "Delete Revoke",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				tags := []string{"tag1", "tag2"}
				(*s).PostDevice(ctx, "alias", "deviceID", "DmsID", "description", tags, "Cg/CgSmartphoneChip", "#0068D1")

			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				e.DELETE("/v1/devices/1/revoke").
					Expect().
					Status(http.StatusOK).JSON()
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},

		{
			name: "Get Device Cert History",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				tags := []string{"tag1", "tag2"}
				(*s).PostDevice(ctx, "alias", "deviceID", "DmsID", "description", tags, "Cg/CgSmartphoneChip", "#0068D1")
			},

			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/devices/1/cert-history").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Array().Length().Equal(1)
				obj.Array().Element(0).Object().ContainsKey("device_id")
				obj.Array().Element(0).Object().ContainsKey("serial_number")
				obj.Array().Element(0).Object().ContainsKey("issuer_name")
				obj.Array().Element(0).Object().ContainsKey("status")
				obj.Array().Element(0).Object().ContainsKey("creation_timestamp")
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},

		{
			name: "GetCertHistoryThirtyDays",
			serviceInitialization: func(s *service.Service) {
			},

			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/devices/dms-cert-history/thirty-days").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Array().Length().Equal(1)
				obj.Array().Element(0).Object().ContainsKey("dms_id")
				obj.Array().Element(0).Object().ContainsKey("issued_certs")
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "GetCertHistoryThirtyDays_NotExistingPath",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(e *httpexpect.Expect) {
				e.GET("/v1/devices/dms-cert-history/thirty-days/thirty-days").
					Expect().
					Status(http.StatusNotFound)
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "Get DMS Last Issued Cert",
			serviceInitialization: func(s *service.Service) {
			},

			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/devices/dms-cert-history/last-issued").
					Expect().
					Status(http.StatusOK).JSON()
				obj.Object().ContainsKey("total_last_issued_cert")
				obj.Object().Value("dms_last_issued_cert").Array().Element(0).Object().ContainsKey("dms_id")
				obj.Object().Value("dms_last_issued_cert").Array().Element(0).Object().ContainsKey("creation_timestamp")
				obj.Object().Value("dms_last_issued_cert").Array().Element(0).Object().ContainsKey("serial_number")

			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		{
			name: "GetDevicesCerts",
			serviceInitialization: func(s *service.Service) {
				ctx := context.Background()
				tags := []string{"tag1", "tag2"}
				(*s).PostDevice(ctx, "alias", "deviceID", "DmsID", "description", tags, "Cg/CgSmartphoneChip", "#0068D1")
			},

			testRestEndpoint: func(e *httpexpect.Expect) {
				obj := e.GET("/v1/devices/1/cert").
					Expect().
					Status(http.StatusOK).JSON()

				obj.Object().ContainsKey("device_id")
				obj.Object().ContainsKey("serial_number")
				obj.Object().ContainsKey("issuer_name")
				obj.Object().ContainsKey("status")
				obj.Object().ContainsKey("crt")
				obj.Object().Value("subject").Object().ContainsKey("common_name")
				obj.Object().Value("subject").Object().ContainsKey("organization")
				obj.Object().Value("subject").Object().ContainsKey("organization_unit")
				obj.Object().Value("subject").Object().ContainsKey("country")
				obj.Object().Value("subject").Object().ContainsKey("state")
				obj.Object().Value("subject").Object().ContainsKey("locality")
				obj.Object().ContainsKey("valid_from")
				obj.Object().ContainsKey("valid_to")
			},
			testEstRestEndpoint: func(s *httpexpect.Expect) {
			},
		},
		//Est-Server tests

		{
			name: "CACerts",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},
			testEstRestEndpoint: func(e *httpexpect.Expect) {
				e.GET("/.well-known/est/cacerts").
					Expect().
					Status(http.StatusOK).ContentType("application/pkcs7-mime")

			},
		},
		{
			name: "CACerts_NotFound",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},
			testEstRestEndpoint: func(e *httpexpect.Expect) {
				e.GET("/.well-known/est/cacerts/c").
					Expect().
					Status(http.StatusNotFound)

			},
		},

		{
			name: "Simpleenroll",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				cert := "-----BEGIN%20CERTIFICATE-----%0AMIIE4jCCAsqgAwIBAgIUYjFME%2Bs8jdOINAtFI5PsL7Ly41UwDQYJKoZIhvcNAQEL%0ABQAwNTEUMBIGA1UEChMLTGFtYXNzdSBQS0kxHTAbBgNVBAMTFExhbWFzc3UgRE1T%0AIEVucm9sbGVyMB4XDTIyMDUwNTEyMzA0NVoXDTQyMDQzMDEyMzExNVowTTEJMAcG%0AA1UEBhMAMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJMAcGA1UEChMAMQkwBwYDVQQL%0AEwAxFDASBgNVBAMTC0RlZmF1bHQtRE1TMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A%0AMIIBigKCAYEA21jRSekUsE3k9MgRmuzaT24zKyfQ007AJYA%2F62KcBkYuyUYDMjGJ%0AhECyAlhvafcMPbaCpa372eeH1icwPo8j8y1LCK21W3YhP4MGGvwjhX%2BI%2F48bGdM8%0AlRDYqlh0X%2Bf6NFWwY%2FMwGCXAEMgDNdUaMfHcYsXbJ79KTyL0lL55cVXk7dhzphCH%0AUL1bfn3Us9h7mqnMkfktPu%2BYFOAd%2Fays%2BSAPF0cC8U4IDpHMaV722ZGJIvjhWEPE%0AUYwwfBeW87cfVSop0tzPz8dem5%2B07ReenMCjtQ0lYrhKn%2FJySSAZh2nFoKmuvJsj%0ABOc%2FHehuF0NrLyGDU93Mm6V87%2FO%2FuX8oNsPRec9S4VNQWPoiVUbI5pHl8uVsDmmr%0Av%2FjkCq5eBLe5s0tan7Hl3hn5WANQ2Nuk4Uy1tJVD79tgX8811mjxxJ5oWAAlcUCC%0A%2FF2kaFgRJYDAWRnoren2lgJqWSSuF%2FYbUy2lfV0voWP%2FVUyDMgKMGtfcHXb4o29c%0APV11v%2FOqNit%2FAgMBAAGjUjBQMA4GA1UdDwEB%2FwQEAwIDqDAdBgNVHQ4EFgQUHhX3%0AsHqH4zgfqf3TKZp%2FD8qwcIAwHwYDVR0jBBgwFoAUFHB%2FZjp0NUI8bui7AB1vd4VB%0A%2FEgwDQYJKoZIhvcNAQELBQADggIBAFZGpZbktfnMEGsDaJ6ekQ%2FfdzD8hpgLNAKa%0AHw8hs3KAvCt%2B1C7o2rGbJqx7%2BU%2Fc9IJ4zWPD8KYA%2FbwYrgdKYzy1I7t8cJebeGS5%0Abc%2Fq0H0EWklzaLC9EIkFW7np2DxfwvNoO7r9e7Zn078YgzolcWs0laiOqAnkQqI2%0AXgwwnuOsCo0hV0CzXRReNKzmWOUSUTsQE%2Fi03I%2FJIvDOfoU5J7Mqi5Soj9fNYsJQ%0ATyJlheBVYfdHysRMQsW5z%2BCMmTpNU1FquTeDGhLn7D9cZT2nFOcTb%2Fs0ekaGr%2Fsy%0AFH9sxo%2BYCLs9W3sMRsKKqtQoth9Vw09MEIX%2BZMe1ULVms8DxtdH6cFa2FMW3XsSh%0AtqvW57u15GtbNZLAc8FNho1%2F6nrNMuWI5n2qQU56C7OLGE%2BiyYW8BKxNybLYGQyV%0As%2FDActKAKTYKhg%2F%2B20oipfXgqVd7KANWd7xPVFhxRE3UloZEmcHJo7MrkrPElofo%0A%2B5Pgz%2BLTKPgYhkbKilm4CQ3dFUsPEocMeWZNaBgC6MBndk6BNXTh05nUuLqbeCpS%0Aip0qthNg5H%2FKEZCKnq98t91huvQm0EAscXPfMAHrUEx0%2BSMQVY1HsMau%2BPJS6TQZ%0ASFonJFm6nYVDn3go%2FZu9VFaIJFkeuKBpSO43Gv6sc7plMJfuPV4LRi54EEdzFj1E%0Abj1P0LLm%0A-----END%20CERTIFICATE-----"

				dmsCert := "Hash=uftufy;Cert=\"" + cert + "\""

				csr, _ := GenerateCSR(rsaKey, "rsa", "Lamassu DMS Enroller")
				reqBody := bytes.NewBuffer(utils.EncodeB64(csr.Raw))

				e.POST("/.well-known/est/Lamassu DMS Enroller/simpleenroll").WithHeader("X-Forwarded-Client-Cert", dmsCert).WithHeader("Content-Type", "application/pkcs10").WithBytes([]byte(
					reqBody.Bytes())).
					Expect().
					Status(http.StatusOK)

			},
		},
		{
			name: "Simpleenroll_BadRequest",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				/*cert := "-----BEGIN%20CERTIFICATE-----%0AMIIFQzCCAysCFFqpO4cc1iGLIj1U1O11dIs9UVktMA0GCSqGSIb3DQEBCwUAMFwx%0ACzAJBgNVBAYTAkVTMREwDwYDVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNh%0AdGUxDDAKBgNVBAoMA0lLTDEMMAoGA1UECwwDWlBEMQswCQYDVQQDDAJDQTAeFw0y%0AMjAyMTYxMTUwMzdaFw0yMzAyMTExMTUwMzdaMGAxCzAJBgNVBAYTAkVTMREwDwYD%0AVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNhdGUxDDAKBgNVBAoMA0lLTDEM%0AMAoGA1UECwwDWlBEMQ8wDQYDVQQDDAZERVZJQ0UwggIiMA0GCSqGSIb3DQEBAQUA%0AA4ICDwAwggIKAoICAQC3lrywkgOu1H%2F6BnDc7NbTEaWSIVkdraRVtKIu2uz5np1O%0AwfBvtSR2N1hzYyZDleCmM4bg9%2F3rLztL7oUxqfjd1TRiTWXheJSBmxdZlhGewjww%0AbycmoGwkxAnlBWi7I0c7fNn6wZ%2Fo23H57%2BzqmpholfWyojU1oRIbSmo5DyKfA7P%2B%0A0VGvVRC5fC1qUzMA8RuDJQTcDeYN3dg6jjz2pkCRbWCCwoJflHRW6QnLQySsestH%0AOvZme1Xf3f3mPeTW0Yya2XWADNw60QueSslE0blrJfI710qWijp6zMJvF1nSC1gK%0AxJwOwzfxYsO%2FQV%2BJrD2zpIXg0JGEwzY8l8ZqZsFokwlDAC%2B9enI%2BgeRQIv6oB9Es%0Aug5c1fdLfR5tWvq1pVv6K7sIoUQ6p71zidXUBjheCnGjxyuyNXq3wKFnTzxAb7Cn%0Axrw84RPtCIMzYOc%2F4J4plBJjGEdh97vdJX5c42VWlQlS%2FvZFXCmpNHGUEBVgmn7T%0ABdHNn%2BhI2Z9s9xOYbD%2BDJh65KTGRUghOTv7ib2T2yzn%2Fa4nSUYZu1pioTtqwOvDH%0ASmhoaoXV%2Fgz2CqF7tVCRSDO1umWa8GbA4amoZXcdN5zk24HF2ItgxNUzE78xNLui%0A0JSHjNKrBnzqQAlpOCF%2BcGJ3SWmumnkBX2AiJYYANylJ2pQhgTEFjyTg1xe%2FbQID%0AAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCS6%2Fggvtq7lIKwzf7B9%2FMP8ns7fAK4H%2BgF%0AiakxCc%2BiAQlPEEyQ0z3hpAepbzsluke8Y76zu3%2F%2BCuomSXf7sB1XyF3sGgSKr%2BKF%0Ava4gm%2Bct9y%2BiP4VfOzyElulPnQxzxoK%2BviPGNVsxCWu4jXnXyPfJDuFutjBAyTxh%0ARgfDpUIukhZYOHN%2F5%2FtOxmF1yhK693OABMpp0mOXi2xcpxEoTYdywIt1tonJ2Yqg%0Aznc%2F0PjMlfubEkBkMTShZ35GdvfU%2F54I5yGsB37iOMi%2BoWs%2FJxKCjP86DUNi%2FfOf%0A0TLYBGZwxPlF%2BOiGwaquAi15xZdQD4HPHzKxF7MeAJ7rmJHDOyRSvsBKtAyU776a%0AwLIgavyfS%2B4%2B0H6uXjfAZH1a1IqUYVDrIVz6cYyEA5lWFDuN0H0r7cIhi7QA5Z6r%0ABEqiBeAPEbheNWJObv0tfdxEZytWnODDcHUVtqOjTSMBHoGbhmpvMnNsQY7eyzaF%0AdgsALyRfK30yCWJ66YKs%2B3cSP6KDPt1ZViPWgI5i91BtAasK%2F7YuVdNe2aHnPDtn%0AxC8ydqts2isrrd3T8lu897IARqPJAVBonwEJ3xOkfVzlTEIwVxycUnoXKk%2FyO5Td%0ANPFHBEvypV%2BQou2wnpmj2xyGaGWu0AL4itwHihDDWDiyU%2FkTzhyET9kO%2Fzjgt03c%0AEOJ3xkZLvA%3D%3D%0A-----END%20CERTIFICATE-----"
				dmsCert := "Hash=uftufy;Cert=\"" + cert + "\""*/

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				csr, _ := GenerateCSR(rsaKey, "rsa", "CA")
				testStruct := estEndpoint.EnrollRequest{
					Csr: csr,
					Aps: "caTest",
					Crt: nil,
				}
				reqBodyBytes := new(bytes.Buffer)
				json.NewEncoder(reqBodyBytes).Encode(testStruct)

				e.POST("/.well-known/est/caTest/simpleenroll").WithBytes([]byte(
					reqBodyBytes.Bytes())).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "Simpleenroll_UnknownAuthority",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				cert := "-----BEGIN%20CERTIFICATE-----%0AMIIFQzCCAysCFFqpO4cc1iGLIj1U1O11dIs9UVktMA0GCSqGSIb3DQEBCwUAMFwx%0ACzAJBgNVBAYTAkVTMREwDwYDVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNh%0AdGUxDDAKBgNVBAoMA0lLTDEMMAoGA1UECwwDWlBEMQswCQYDVQQDDAJDQTAeFw0y%0AMjAyMTYxMTUwMzdaFw0yMzAyMTExMTUwMzdaMGAxCzAJBgNVBAYTAkVTMREwDwYD%0AVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNhdGUxDDAKBgNVBAoMA0lLTDEM%0AMAoGA1UECwwDWlBEMQ8wDQYDVQQDDAZERVZJQ0UwggIiMA0GCSqGSIb3DQEBAQUA%0AA4ICDwAwggIKAoICAQC3lrywkgOu1H%2F6BnDc7NbTEaWSIVkdraRVtKIu2uz5np1O%0AwfBvtSR2N1hzYyZDleCmM4bg9%2F3rLztL7oUxqfjd1TRiTWXheJSBmxdZlhGewjww%0AbycmoGwkxAnlBWi7I0c7fNn6wZ%2Fo23H57%2BzqmpholfWyojU1oRIbSmo5DyKfA7P%2B%0A0VGvVRC5fC1qUzMA8RuDJQTcDeYN3dg6jjz2pkCRbWCCwoJflHRW6QnLQySsestH%0AOvZme1Xf3f3mPeTW0Yya2XWADNw60QueSslE0blrJfI710qWijp6zMJvF1nSC1gK%0AxJwOwzfxYsO%2FQV%2BJrD2zpIXg0JGEwzY8l8ZqZsFokwlDAC%2B9enI%2BgeRQIv6oB9Es%0Aug5c1fdLfR5tWvq1pVv6K7sIoUQ6p71zidXUBjheCnGjxyuyNXq3wKFnTzxAb7Cn%0Axrw84RPtCIMzYOc%2F4J4plBJjGEdh97vdJX5c42VWlQlS%2FvZFXCmpNHGUEBVgmn7T%0ABdHNn%2BhI2Z9s9xOYbD%2BDJh65KTGRUghOTv7ib2T2yzn%2Fa4nSUYZu1pioTtqwOvDH%0ASmhoaoXV%2Fgz2CqF7tVCRSDO1umWa8GbA4amoZXcdN5zk24HF2ItgxNUzE78xNLui%0A0JSHjNKrBnzqQAlpOCF%2BcGJ3SWmumnkBX2AiJYYANylJ2pQhgTEFjyTg1xe%2FbQID%0AAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCS6%2Fggvtq7lIKwzf7B9%2FMP8ns7fAK4H%2BgF%0AiakxCc%2BiAQlPEEyQ0z3hpAepbzsluke8Y76zu3%2F%2BCuomSXf7sB1XyF3sGgSKr%2BKF%0Ava4gm%2Bct9y%2BiP4VfOzyElulPnQxzxoK%2BviPGNVsxCWu4jXnXyPfJDuFutjBAyTxh%0ARgfDpUIukhZYOHN%2F5%2FtOxmF1yhK693OABMpp0mOXi2xcpxEoTYdywIt1tonJ2Yqg%0Aznc%2F0PjMlfubEkBkMTShZ35GdvfU%2F54I5yGsB37iOMi%2BoWs%2FJxKCjP86DUNi%2FfOf%0A0TLYBGZwxPlF%2BOiGwaquAi15xZdQD4HPHzKxF7MeAJ7rmJHDOyRSvsBKtAyU776a%0AwLIgavyfS%2B4%2B0H6uXjfAZH1a1IqUYVDrIVz6cYyEA5lWFDuN0H0r7cIhi7QA5Z6r%0ABEqiBeAPEbheNWJObv0tfdxEZytWnODDcHUVtqOjTSMBHoGbhmpvMnNsQY7eyzaF%0AdgsALyRfK30yCWJ66YKs%2B3cSP6KDPt1ZViPWgI5i91BtAasK%2F7YuVdNe2aHnPDtn%0AxC8ydqts2isrrd3T8lu897IARqPJAVBonwEJ3xOkfVzlTEIwVxycUnoXKk%2FyO5Td%0ANPFHBEvypV%2BQou2wnpmj2xyGaGWu0AL4itwHihDDWDiyU%2FkTzhyET9kO%2Fzjgt03c%0AEOJ3xkZLvA%3D%3D%0A-----END%20CERTIFICATE-----"
				dmsCert := "Hash=uftufy;Cert=\"" + cert + "\""

				csr, _ := GenerateCSR(rsaKey, "rsa", "CA")
				reqBody := bytes.NewBuffer(utils.EncodeB64(csr.Raw))

				e.POST("/.well-known/est/CA/simpleenroll").WithHeader("X-Forwarded-Client-Cert", dmsCert).WithHeader("Content-Type", "application/pkcs10").WithBytes([]byte(
					reqBody.Bytes())).
					Expect().
					Status(http.StatusInternalServerError)

			},
		},
		{
			name: "Simpleenroll_ErrMissingAPS",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				cert := "-----BEGIN%20CERTIFICATE-----%0AMIIE4jCCAsqgAwIBAgIUYjFME%2Bs8jdOINAtFI5PsL7Ly41UwDQYJKoZIhvcNAQEL%0ABQAwNTEUMBIGA1UEChMLTGFtYXNzdSBQS0kxHTAbBgNVBAMTFExhbWFzc3UgRE1T%0AIEVucm9sbGVyMB4XDTIyMDUwNTEyMzA0NVoXDTQyMDQzMDEyMzExNVowTTEJMAcG%0AA1UEBhMAMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJMAcGA1UEChMAMQkwBwYDVQQL%0AEwAxFDASBgNVBAMTC0RlZmF1bHQtRE1TMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A%0AMIIBigKCAYEA21jRSekUsE3k9MgRmuzaT24zKyfQ007AJYA%2F62KcBkYuyUYDMjGJ%0AhECyAlhvafcMPbaCpa372eeH1icwPo8j8y1LCK21W3YhP4MGGvwjhX%2BI%2F48bGdM8%0AlRDYqlh0X%2Bf6NFWwY%2FMwGCXAEMgDNdUaMfHcYsXbJ79KTyL0lL55cVXk7dhzphCH%0AUL1bfn3Us9h7mqnMkfktPu%2BYFOAd%2Fays%2BSAPF0cC8U4IDpHMaV722ZGJIvjhWEPE%0AUYwwfBeW87cfVSop0tzPz8dem5%2B07ReenMCjtQ0lYrhKn%2FJySSAZh2nFoKmuvJsj%0ABOc%2FHehuF0NrLyGDU93Mm6V87%2FO%2FuX8oNsPRec9S4VNQWPoiVUbI5pHl8uVsDmmr%0Av%2FjkCq5eBLe5s0tan7Hl3hn5WANQ2Nuk4Uy1tJVD79tgX8811mjxxJ5oWAAlcUCC%0A%2FF2kaFgRJYDAWRnoren2lgJqWSSuF%2FYbUy2lfV0voWP%2FVUyDMgKMGtfcHXb4o29c%0APV11v%2FOqNit%2FAgMBAAGjUjBQMA4GA1UdDwEB%2FwQEAwIDqDAdBgNVHQ4EFgQUHhX3%0AsHqH4zgfqf3TKZp%2FD8qwcIAwHwYDVR0jBBgwFoAUFHB%2FZjp0NUI8bui7AB1vd4VB%0A%2FEgwDQYJKoZIhvcNAQELBQADggIBAFZGpZbktfnMEGsDaJ6ekQ%2FfdzD8hpgLNAKa%0AHw8hs3KAvCt%2B1C7o2rGbJqx7%2BU%2Fc9IJ4zWPD8KYA%2FbwYrgdKYzy1I7t8cJebeGS5%0Abc%2Fq0H0EWklzaLC9EIkFW7np2DxfwvNoO7r9e7Zn078YgzolcWs0laiOqAnkQqI2%0AXgwwnuOsCo0hV0CzXRReNKzmWOUSUTsQE%2Fi03I%2FJIvDOfoU5J7Mqi5Soj9fNYsJQ%0ATyJlheBVYfdHysRMQsW5z%2BCMmTpNU1FquTeDGhLn7D9cZT2nFOcTb%2Fs0ekaGr%2Fsy%0AFH9sxo%2BYCLs9W3sMRsKKqtQoth9Vw09MEIX%2BZMe1ULVms8DxtdH6cFa2FMW3XsSh%0AtqvW57u15GtbNZLAc8FNho1%2F6nrNMuWI5n2qQU56C7OLGE%2BiyYW8BKxNybLYGQyV%0As%2FDActKAKTYKhg%2F%2B20oipfXgqVd7KANWd7xPVFhxRE3UloZEmcHJo7MrkrPElofo%0A%2B5Pgz%2BLTKPgYhkbKilm4CQ3dFUsPEocMeWZNaBgC6MBndk6BNXTh05nUuLqbeCpS%0Aip0qthNg5H%2FKEZCKnq98t91huvQm0EAscXPfMAHrUEx0%2BSMQVY1HsMau%2BPJS6TQZ%0ASFonJFm6nYVDn3go%2FZu9VFaIJFkeuKBpSO43Gv6sc7plMJfuPV4LRi54EEdzFj1E%0Abj1P0LLm%0A-----END%20CERTIFICATE-----"
				//cert := "-----BEGIN%20CERTIFICATE-----%0AMIIFQzCCAysCFFqpO4cc1iGLIj1U1O11dIs9UVktMA0GCSqGSIb3DQEBCwUAMFwx%0ACzAJBgNVBAYTAkVTMREwDwYDVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNh%0AdGUxDDAKBgNVBAoMA0lLTDEMMAoGA1UECwwDWlBEMQswCQYDVQQDDAJDQTAeFw0y%0AMjAyMTYxMTUwMzdaFw0yMzAyMTExMTUwMzdaMGAxCzAJBgNVBAYTAkVTMREwDwYD%0AVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNhdGUxDDAKBgNVBAoMA0lLTDEM%0AMAoGA1UECwwDWlBEMQ8wDQYDVQQDDAZERVZJQ0UwggIiMA0GCSqGSIb3DQEBAQUA%0AA4ICDwAwggIKAoICAQC3lrywkgOu1H%2F6BnDc7NbTEaWSIVkdraRVtKIu2uz5np1O%0AwfBvtSR2N1hzYyZDleCmM4bg9%2F3rLztL7oUxqfjd1TRiTWXheJSBmxdZlhGewjww%0AbycmoGwkxAnlBWi7I0c7fNn6wZ%2Fo23H57%2BzqmpholfWyojU1oRIbSmo5DyKfA7P%2B%0A0VGvVRC5fC1qUzMA8RuDJQTcDeYN3dg6jjz2pkCRbWCCwoJflHRW6QnLQySsestH%0AOvZme1Xf3f3mPeTW0Yya2XWADNw60QueSslE0blrJfI710qWijp6zMJvF1nSC1gK%0AxJwOwzfxYsO%2FQV%2BJrD2zpIXg0JGEwzY8l8ZqZsFokwlDAC%2B9enI%2BgeRQIv6oB9Es%0Aug5c1fdLfR5tWvq1pVv6K7sIoUQ6p71zidXUBjheCnGjxyuyNXq3wKFnTzxAb7Cn%0Axrw84RPtCIMzYOc%2F4J4plBJjGEdh97vdJX5c42VWlQlS%2FvZFXCmpNHGUEBVgmn7T%0ABdHNn%2BhI2Z9s9xOYbD%2BDJh65KTGRUghOTv7ib2T2yzn%2Fa4nSUYZu1pioTtqwOvDH%0ASmhoaoXV%2Fgz2CqF7tVCRSDO1umWa8GbA4amoZXcdN5zk24HF2ItgxNUzE78xNLui%0A0JSHjNKrBnzqQAlpOCF%2BcGJ3SWmumnkBX2AiJYYANylJ2pQhgTEFjyTg1xe%2FbQID%0AAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCS6%2Fggvtq7lIKwzf7B9%2FMP8ns7fAK4H%2BgF%0AiakxCc%2BiAQlPEEyQ0z3hpAepbzsluke8Y76zu3%2F%2BCuomSXf7sB1XyF3sGgSKr%2BKF%0Ava4gm%2Bct9y%2BiP4VfOzyElulPnQxzxoK%2BviPGNVsxCWu4jXnXyPfJDuFutjBAyTxh%0ARgfDpUIukhZYOHN%2F5%2FtOxmF1yhK693OABMpp0mOXi2xcpxEoTYdywIt1tonJ2Yqg%0Aznc%2F0PjMlfubEkBkMTShZ35GdvfU%2F54I5yGsB37iOMi%2BoWs%2FJxKCjP86DUNi%2FfOf%0A0TLYBGZwxPlF%2BOiGwaquAi15xZdQD4HPHzKxF7MeAJ7rmJHDOyRSvsBKtAyU776a%0AwLIgavyfS%2B4%2B0H6uXjfAZH1a1IqUYVDrIVz6cYyEA5lWFDuN0H0r7cIhi7QA5Z6r%0ABEqiBeAPEbheNWJObv0tfdxEZytWnODDcHUVtqOjTSMBHoGbhmpvMnNsQY7eyzaF%0AdgsALyRfK30yCWJ66YKs%2B3cSP6KDPt1ZViPWgI5i91BtAasK%2F7YuVdNe2aHnPDtn%0AxC8ydqts2isrrd3T8lu897IARqPJAVBonwEJ3xOkfVzlTEIwVxycUnoXKk%2FyO5Td%0ANPFHBEvypV%2BQou2wnpmj2xyGaGWu0AL4itwHihDDWDiyU%2FkTzhyET9kO%2Fzjgt03c%0AEOJ3xkZLvA%3D%3D%0A-----END%20CERTIFICATE-----"

				dmsCert := "Hash=uftufy;Cert=\"" + cert + "\""

				csr, _ := GenerateCSR(rsaKey, "rsa", "CA")
				reqBody := bytes.NewBuffer(utils.EncodeB64(csr.Raw))

				e.POST("/.well-known/est//simpleenroll").WithHeader("X-Forwarded-Client-Cert", dmsCert).WithHeader("Content-Type", "application/pkcs10").WithBytes([]byte(
					reqBody.Bytes())).
					Expect().
					Status(http.StatusNotFound)

			},
		},
		{
			name: "Simpleenroll_ErrContentType",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				cert := "-----BEGIN%20CERTIFICATE-----%0AMIIFQzCCAysCFFqpO4cc1iGLIj1U1O11dIs9UVktMA0GCSqGSIb3DQEBCwUAMFwx%0ACzAJBgNVBAYTAkVTMREwDwYDVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNh%0AdGUxDDAKBgNVBAoMA0lLTDEMMAoGA1UECwwDWlBEMQswCQYDVQQDDAJDQTAeFw0y%0AMjAyMTYxMTUwMzdaFw0yMzAyMTExMTUwMzdaMGAxCzAJBgNVBAYTAkVTMREwDwYD%0AVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNhdGUxDDAKBgNVBAoMA0lLTDEM%0AMAoGA1UECwwDWlBEMQ8wDQYDVQQDDAZERVZJQ0UwggIiMA0GCSqGSIb3DQEBAQUA%0AA4ICDwAwggIKAoICAQC3lrywkgOu1H%2F6BnDc7NbTEaWSIVkdraRVtKIu2uz5np1O%0AwfBvtSR2N1hzYyZDleCmM4bg9%2F3rLztL7oUxqfjd1TRiTWXheJSBmxdZlhGewjww%0AbycmoGwkxAnlBWi7I0c7fNn6wZ%2Fo23H57%2BzqmpholfWyojU1oRIbSmo5DyKfA7P%2B%0A0VGvVRC5fC1qUzMA8RuDJQTcDeYN3dg6jjz2pkCRbWCCwoJflHRW6QnLQySsestH%0AOvZme1Xf3f3mPeTW0Yya2XWADNw60QueSslE0blrJfI710qWijp6zMJvF1nSC1gK%0AxJwOwzfxYsO%2FQV%2BJrD2zpIXg0JGEwzY8l8ZqZsFokwlDAC%2B9enI%2BgeRQIv6oB9Es%0Aug5c1fdLfR5tWvq1pVv6K7sIoUQ6p71zidXUBjheCnGjxyuyNXq3wKFnTzxAb7Cn%0Axrw84RPtCIMzYOc%2F4J4plBJjGEdh97vdJX5c42VWlQlS%2FvZFXCmpNHGUEBVgmn7T%0ABdHNn%2BhI2Z9s9xOYbD%2BDJh65KTGRUghOTv7ib2T2yzn%2Fa4nSUYZu1pioTtqwOvDH%0ASmhoaoXV%2Fgz2CqF7tVCRSDO1umWa8GbA4amoZXcdN5zk24HF2ItgxNUzE78xNLui%0A0JSHjNKrBnzqQAlpOCF%2BcGJ3SWmumnkBX2AiJYYANylJ2pQhgTEFjyTg1xe%2FbQID%0AAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCS6%2Fggvtq7lIKwzf7B9%2FMP8ns7fAK4H%2BgF%0AiakxCc%2BiAQlPEEyQ0z3hpAepbzsluke8Y76zu3%2F%2BCuomSXf7sB1XyF3sGgSKr%2BKF%0Ava4gm%2Bct9y%2BiP4VfOzyElulPnQxzxoK%2BviPGNVsxCWu4jXnXyPfJDuFutjBAyTxh%0ARgfDpUIukhZYOHN%2F5%2FtOxmF1yhK693OABMpp0mOXi2xcpxEoTYdywIt1tonJ2Yqg%0Aznc%2F0PjMlfubEkBkMTShZ35GdvfU%2F54I5yGsB37iOMi%2BoWs%2FJxKCjP86DUNi%2FfOf%0A0TLYBGZwxPlF%2BOiGwaquAi15xZdQD4HPHzKxF7MeAJ7rmJHDOyRSvsBKtAyU776a%0AwLIgavyfS%2B4%2B0H6uXjfAZH1a1IqUYVDrIVz6cYyEA5lWFDuN0H0r7cIhi7QA5Z6r%0ABEqiBeAPEbheNWJObv0tfdxEZytWnODDcHUVtqOjTSMBHoGbhmpvMnNsQY7eyzaF%0AdgsALyRfK30yCWJ66YKs%2B3cSP6KDPt1ZViPWgI5i91BtAasK%2F7YuVdNe2aHnPDtn%0AxC8ydqts2isrrd3T8lu897IARqPJAVBonwEJ3xOkfVzlTEIwVxycUnoXKk%2FyO5Td%0ANPFHBEvypV%2BQou2wnpmj2xyGaGWu0AL4itwHihDDWDiyU%2FkTzhyET9kO%2Fzjgt03c%0AEOJ3xkZLvA%3D%3D%0A-----END%20CERTIFICATE-----"
				dmsCert := "Hash=uftufy;Cert=\"" + cert + "\""

				csr, _ := GenerateCSR(rsaKey, "rsa", "CA")
				reqBody := bytes.NewBuffer(utils.EncodeB64(csr.Raw))

				e.POST("/.well-known/est/caTest/simpleenroll").WithHeader("X-Forwarded-Client-Cert", dmsCert).WithHeader("Content-Type", "application/json").WithBytes([]byte(
					reqBody.Bytes())).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "Reenroll_ErrContentType",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				cert := "-----BEGIN%20CERTIFICATE-----%0AMIIFQzCCAysCFFqpO4cc1iGLIj1U1O11dIs9UVktMA0GCSqGSIb3DQEBCwUAMFwx%0ACzAJBgNVBAYTAkVTMREwDwYDVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNh%0AdGUxDDAKBgNVBAoMA0lLTDEMMAoGA1UECwwDWlBEMQswCQYDVQQDDAJDQTAeFw0y%0AMjAyMTYxMTUwMzdaFw0yMzAyMTExMTUwMzdaMGAxCzAJBgNVBAYTAkVTMREwDwYD%0AVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNhdGUxDDAKBgNVBAoMA0lLTDEM%0AMAoGA1UECwwDWlBEMQ8wDQYDVQQDDAZERVZJQ0UwggIiMA0GCSqGSIb3DQEBAQUA%0AA4ICDwAwggIKAoICAQC3lrywkgOu1H%2F6BnDc7NbTEaWSIVkdraRVtKIu2uz5np1O%0AwfBvtSR2N1hzYyZDleCmM4bg9%2F3rLztL7oUxqfjd1TRiTWXheJSBmxdZlhGewjww%0AbycmoGwkxAnlBWi7I0c7fNn6wZ%2Fo23H57%2BzqmpholfWyojU1oRIbSmo5DyKfA7P%2B%0A0VGvVRC5fC1qUzMA8RuDJQTcDeYN3dg6jjz2pkCRbWCCwoJflHRW6QnLQySsestH%0AOvZme1Xf3f3mPeTW0Yya2XWADNw60QueSslE0blrJfI710qWijp6zMJvF1nSC1gK%0AxJwOwzfxYsO%2FQV%2BJrD2zpIXg0JGEwzY8l8ZqZsFokwlDAC%2B9enI%2BgeRQIv6oB9Es%0Aug5c1fdLfR5tWvq1pVv6K7sIoUQ6p71zidXUBjheCnGjxyuyNXq3wKFnTzxAb7Cn%0Axrw84RPtCIMzYOc%2F4J4plBJjGEdh97vdJX5c42VWlQlS%2FvZFXCmpNHGUEBVgmn7T%0ABdHNn%2BhI2Z9s9xOYbD%2BDJh65KTGRUghOTv7ib2T2yzn%2Fa4nSUYZu1pioTtqwOvDH%0ASmhoaoXV%2Fgz2CqF7tVCRSDO1umWa8GbA4amoZXcdN5zk24HF2ItgxNUzE78xNLui%0A0JSHjNKrBnzqQAlpOCF%2BcGJ3SWmumnkBX2AiJYYANylJ2pQhgTEFjyTg1xe%2FbQID%0AAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCS6%2Fggvtq7lIKwzf7B9%2FMP8ns7fAK4H%2BgF%0AiakxCc%2BiAQlPEEyQ0z3hpAepbzsluke8Y76zu3%2F%2BCuomSXf7sB1XyF3sGgSKr%2BKF%0Ava4gm%2Bct9y%2BiP4VfOzyElulPnQxzxoK%2BviPGNVsxCWu4jXnXyPfJDuFutjBAyTxh%0ARgfDpUIukhZYOHN%2F5%2FtOxmF1yhK693OABMpp0mOXi2xcpxEoTYdywIt1tonJ2Yqg%0Aznc%2F0PjMlfubEkBkMTShZ35GdvfU%2F54I5yGsB37iOMi%2BoWs%2FJxKCjP86DUNi%2FfOf%0A0TLYBGZwxPlF%2BOiGwaquAi15xZdQD4HPHzKxF7MeAJ7rmJHDOyRSvsBKtAyU776a%0AwLIgavyfS%2B4%2B0H6uXjfAZH1a1IqUYVDrIVz6cYyEA5lWFDuN0H0r7cIhi7QA5Z6r%0ABEqiBeAPEbheNWJObv0tfdxEZytWnODDcHUVtqOjTSMBHoGbhmpvMnNsQY7eyzaF%0AdgsALyRfK30yCWJ66YKs%2B3cSP6KDPt1ZViPWgI5i91BtAasK%2F7YuVdNe2aHnPDtn%0AxC8ydqts2isrrd3T8lu897IARqPJAVBonwEJ3xOkfVzlTEIwVxycUnoXKk%2FyO5Td%0ANPFHBEvypV%2BQou2wnpmj2xyGaGWu0AL4itwHihDDWDiyU%2FkTzhyET9kO%2Fzjgt03c%0AEOJ3xkZLvA%3D%3D%0A-----END%20CERTIFICATE-----"
				dmsCert := "Hash=uftufy;Cert=\"" + cert + "\""

				csr, _ := GenerateCSR(rsaKey, "rsa", "DEVICE")
				reqBody := bytes.NewBuffer(utils.EncodeB64(csr.Raw))

				e.POST("/.well-known/est/simplereenroll").WithHeader("X-Forwarded-Client-Cert", dmsCert).WithHeader("Content-Type", "application/json").WithBytes([]byte(
					reqBody.Bytes())).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "Reenroll",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				cert := "-----BEGIN%20CERTIFICATE-----%0AMIIFQzCCAysCFFqpO4cc1iGLIj1U1O11dIs9UVktMA0GCSqGSIb3DQEBCwUAMFwx%0ACzAJBgNVBAYTAkVTMREwDwYDVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNh%0AdGUxDDAKBgNVBAoMA0lLTDEMMAoGA1UECwwDWlBEMQswCQYDVQQDDAJDQTAeFw0y%0AMjAyMTYxMTUwMzdaFw0yMzAyMTExMTUwMzdaMGAxCzAJBgNVBAYTAkVTMREwDwYD%0AVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNhdGUxDDAKBgNVBAoMA0lLTDEM%0AMAoGA1UECwwDWlBEMQ8wDQYDVQQDDAZERVZJQ0UwggIiMA0GCSqGSIb3DQEBAQUA%0AA4ICDwAwggIKAoICAQC3lrywkgOu1H%2F6BnDc7NbTEaWSIVkdraRVtKIu2uz5np1O%0AwfBvtSR2N1hzYyZDleCmM4bg9%2F3rLztL7oUxqfjd1TRiTWXheJSBmxdZlhGewjww%0AbycmoGwkxAnlBWi7I0c7fNn6wZ%2Fo23H57%2BzqmpholfWyojU1oRIbSmo5DyKfA7P%2B%0A0VGvVRC5fC1qUzMA8RuDJQTcDeYN3dg6jjz2pkCRbWCCwoJflHRW6QnLQySsestH%0AOvZme1Xf3f3mPeTW0Yya2XWADNw60QueSslE0blrJfI710qWijp6zMJvF1nSC1gK%0AxJwOwzfxYsO%2FQV%2BJrD2zpIXg0JGEwzY8l8ZqZsFokwlDAC%2B9enI%2BgeRQIv6oB9Es%0Aug5c1fdLfR5tWvq1pVv6K7sIoUQ6p71zidXUBjheCnGjxyuyNXq3wKFnTzxAb7Cn%0Axrw84RPtCIMzYOc%2F4J4plBJjGEdh97vdJX5c42VWlQlS%2FvZFXCmpNHGUEBVgmn7T%0ABdHNn%2BhI2Z9s9xOYbD%2BDJh65KTGRUghOTv7ib2T2yzn%2Fa4nSUYZu1pioTtqwOvDH%0ASmhoaoXV%2Fgz2CqF7tVCRSDO1umWa8GbA4amoZXcdN5zk24HF2ItgxNUzE78xNLui%0A0JSHjNKrBnzqQAlpOCF%2BcGJ3SWmumnkBX2AiJYYANylJ2pQhgTEFjyTg1xe%2FbQID%0AAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCS6%2Fggvtq7lIKwzf7B9%2FMP8ns7fAK4H%2BgF%0AiakxCc%2BiAQlPEEyQ0z3hpAepbzsluke8Y76zu3%2F%2BCuomSXf7sB1XyF3sGgSKr%2BKF%0Ava4gm%2Bct9y%2BiP4VfOzyElulPnQxzxoK%2BviPGNVsxCWu4jXnXyPfJDuFutjBAyTxh%0ARgfDpUIukhZYOHN%2F5%2FtOxmF1yhK693OABMpp0mOXi2xcpxEoTYdywIt1tonJ2Yqg%0Aznc%2F0PjMlfubEkBkMTShZ35GdvfU%2F54I5yGsB37iOMi%2BoWs%2FJxKCjP86DUNi%2FfOf%0A0TLYBGZwxPlF%2BOiGwaquAi15xZdQD4HPHzKxF7MeAJ7rmJHDOyRSvsBKtAyU776a%0AwLIgavyfS%2B4%2B0H6uXjfAZH1a1IqUYVDrIVz6cYyEA5lWFDuN0H0r7cIhi7QA5Z6r%0ABEqiBeAPEbheNWJObv0tfdxEZytWnODDcHUVtqOjTSMBHoGbhmpvMnNsQY7eyzaF%0AdgsALyRfK30yCWJ66YKs%2B3cSP6KDPt1ZViPWgI5i91BtAasK%2F7YuVdNe2aHnPDtn%0AxC8ydqts2isrrd3T8lu897IARqPJAVBonwEJ3xOkfVzlTEIwVxycUnoXKk%2FyO5Td%0ANPFHBEvypV%2BQou2wnpmj2xyGaGWu0AL4itwHihDDWDiyU%2FkTzhyET9kO%2Fzjgt03c%0AEOJ3xkZLvA%3D%3D%0A-----END%20CERTIFICATE-----"
				dmsCert := "Hash=uftufy;Cert=\"" + cert + "\""

				csr, _ := GenerateCSR(rsaKey, "rsa", "DEVICE")
				reqBody := bytes.NewBuffer(utils.EncodeB64(csr.Raw))

				e.POST("/.well-known/est/simplereenroll").WithHeader("X-Forwarded-Client-Cert", dmsCert).WithHeader("Content-Type", "application/pkcs10").WithBytes([]byte(
					reqBody.Bytes())).
					Expect().
					Status(http.StatusOK)
			},
		},

		{
			name: "Reenroll_BadRequest",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				csr, _ := GenerateCSR(rsaKey, "rsa", "CA")
				testStruct := estEndpoint.EnrollRequest{
					Csr: csr,
					Aps: "caTest",
					Crt: nil,
				}
				reqBodyBytes := new(bytes.Buffer)
				json.NewEncoder(reqBodyBytes).Encode(testStruct)

				e.POST("/.well-known/est/simplereenroll").WithBytes([]byte(
					reqBodyBytes.Bytes())).
					Expect().
					Status(http.StatusBadRequest)
			},
		},
		{
			name: "ServerKeyGen",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				cert := "-----BEGIN%20CERTIFICATE-----%0AMIIE4jCCAsqgAwIBAgIUYjFME%2Bs8jdOINAtFI5PsL7Ly41UwDQYJKoZIhvcNAQEL%0ABQAwNTEUMBIGA1UEChMLTGFtYXNzdSBQS0kxHTAbBgNVBAMTFExhbWFzc3UgRE1T%0AIEVucm9sbGVyMB4XDTIyMDUwNTEyMzA0NVoXDTQyMDQzMDEyMzExNVowTTEJMAcG%0AA1UEBhMAMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJMAcGA1UEChMAMQkwBwYDVQQL%0AEwAxFDASBgNVBAMTC0RlZmF1bHQtRE1TMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A%0AMIIBigKCAYEA21jRSekUsE3k9MgRmuzaT24zKyfQ007AJYA%2F62KcBkYuyUYDMjGJ%0AhECyAlhvafcMPbaCpa372eeH1icwPo8j8y1LCK21W3YhP4MGGvwjhX%2BI%2F48bGdM8%0AlRDYqlh0X%2Bf6NFWwY%2FMwGCXAEMgDNdUaMfHcYsXbJ79KTyL0lL55cVXk7dhzphCH%0AUL1bfn3Us9h7mqnMkfktPu%2BYFOAd%2Fays%2BSAPF0cC8U4IDpHMaV722ZGJIvjhWEPE%0AUYwwfBeW87cfVSop0tzPz8dem5%2B07ReenMCjtQ0lYrhKn%2FJySSAZh2nFoKmuvJsj%0ABOc%2FHehuF0NrLyGDU93Mm6V87%2FO%2FuX8oNsPRec9S4VNQWPoiVUbI5pHl8uVsDmmr%0Av%2FjkCq5eBLe5s0tan7Hl3hn5WANQ2Nuk4Uy1tJVD79tgX8811mjxxJ5oWAAlcUCC%0A%2FF2kaFgRJYDAWRnoren2lgJqWSSuF%2FYbUy2lfV0voWP%2FVUyDMgKMGtfcHXb4o29c%0APV11v%2FOqNit%2FAgMBAAGjUjBQMA4GA1UdDwEB%2FwQEAwIDqDAdBgNVHQ4EFgQUHhX3%0AsHqH4zgfqf3TKZp%2FD8qwcIAwHwYDVR0jBBgwFoAUFHB%2FZjp0NUI8bui7AB1vd4VB%0A%2FEgwDQYJKoZIhvcNAQELBQADggIBAFZGpZbktfnMEGsDaJ6ekQ%2FfdzD8hpgLNAKa%0AHw8hs3KAvCt%2B1C7o2rGbJqx7%2BU%2Fc9IJ4zWPD8KYA%2FbwYrgdKYzy1I7t8cJebeGS5%0Abc%2Fq0H0EWklzaLC9EIkFW7np2DxfwvNoO7r9e7Zn078YgzolcWs0laiOqAnkQqI2%0AXgwwnuOsCo0hV0CzXRReNKzmWOUSUTsQE%2Fi03I%2FJIvDOfoU5J7Mqi5Soj9fNYsJQ%0ATyJlheBVYfdHysRMQsW5z%2BCMmTpNU1FquTeDGhLn7D9cZT2nFOcTb%2Fs0ekaGr%2Fsy%0AFH9sxo%2BYCLs9W3sMRsKKqtQoth9Vw09MEIX%2BZMe1ULVms8DxtdH6cFa2FMW3XsSh%0AtqvW57u15GtbNZLAc8FNho1%2F6nrNMuWI5n2qQU56C7OLGE%2BiyYW8BKxNybLYGQyV%0As%2FDActKAKTYKhg%2F%2B20oipfXgqVd7KANWd7xPVFhxRE3UloZEmcHJo7MrkrPElofo%0A%2B5Pgz%2BLTKPgYhkbKilm4CQ3dFUsPEocMeWZNaBgC6MBndk6BNXTh05nUuLqbeCpS%0Aip0qthNg5H%2FKEZCKnq98t91huvQm0EAscXPfMAHrUEx0%2BSMQVY1HsMau%2BPJS6TQZ%0ASFonJFm6nYVDn3go%2FZu9VFaIJFkeuKBpSO43Gv6sc7plMJfuPV4LRi54EEdzFj1E%0Abj1P0LLm%0A-----END%20CERTIFICATE-----"
				dmsCert := "Hash=uftufy;Cert=\"" + cert + "\""

				csr, _ := GenerateCSR(rsaKey, "rsa", "Lamassu DMS Enroller")
				reqBody := bytes.NewBuffer(utils.EncodeB64(csr.Raw))

				e.POST("/.well-known/est/Lamassu DMS Enroller/serverkeygen").WithHeader("X-Forwarded-Client-Cert", dmsCert).WithHeader("Content-Type", "application/pkcs10").WithBytes([]byte(
					reqBody.Bytes())).
					Expect().
					Status(http.StatusOK)

			},
		},
		{
			name: "ServerKeyGen_BadRequest",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				csr, _ := GenerateCSR(rsaKey, "rsa", "CA")
				testStruct := estEndpoint.EnrollRequest{
					Csr: csr,
					Aps: "caTest",
					Crt: nil,
				}
				reqBodyBytes := new(bytes.Buffer)
				json.NewEncoder(reqBodyBytes).Encode(testStruct)

				e.POST("/.well-known/est/IkerCA/serverkeygen").WithBytes([]byte(
					reqBodyBytes.Bytes())).
					Expect().
					Status(http.StatusBadRequest)

			},
		},
		{
			name: "ServerKeyGen_UnknownAuthority",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				cert := "-----BEGIN%20CERTIFICATE-----%0AMIIFQzCCAysCFFqpO4cc1iGLIj1U1O11dIs9UVktMA0GCSqGSIb3DQEBCwUAMFwx%0ACzAJBgNVBAYTAkVTMREwDwYDVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNh%0AdGUxDDAKBgNVBAoMA0lLTDEMMAoGA1UECwwDWlBEMQswCQYDVQQDDAJDQTAeFw0y%0AMjAyMTYxMTUwMzdaFw0yMzAyMTExMTUwMzdaMGAxCzAJBgNVBAYTAkVTMREwDwYD%0AVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNhdGUxDDAKBgNVBAoMA0lLTDEM%0AMAoGA1UECwwDWlBEMQ8wDQYDVQQDDAZERVZJQ0UwggIiMA0GCSqGSIb3DQEBAQUA%0AA4ICDwAwggIKAoICAQC3lrywkgOu1H%2F6BnDc7NbTEaWSIVkdraRVtKIu2uz5np1O%0AwfBvtSR2N1hzYyZDleCmM4bg9%2F3rLztL7oUxqfjd1TRiTWXheJSBmxdZlhGewjww%0AbycmoGwkxAnlBWi7I0c7fNn6wZ%2Fo23H57%2BzqmpholfWyojU1oRIbSmo5DyKfA7P%2B%0A0VGvVRC5fC1qUzMA8RuDJQTcDeYN3dg6jjz2pkCRbWCCwoJflHRW6QnLQySsestH%0AOvZme1Xf3f3mPeTW0Yya2XWADNw60QueSslE0blrJfI710qWijp6zMJvF1nSC1gK%0AxJwOwzfxYsO%2FQV%2BJrD2zpIXg0JGEwzY8l8ZqZsFokwlDAC%2B9enI%2BgeRQIv6oB9Es%0Aug5c1fdLfR5tWvq1pVv6K7sIoUQ6p71zidXUBjheCnGjxyuyNXq3wKFnTzxAb7Cn%0Axrw84RPtCIMzYOc%2F4J4plBJjGEdh97vdJX5c42VWlQlS%2FvZFXCmpNHGUEBVgmn7T%0ABdHNn%2BhI2Z9s9xOYbD%2BDJh65KTGRUghOTv7ib2T2yzn%2Fa4nSUYZu1pioTtqwOvDH%0ASmhoaoXV%2Fgz2CqF7tVCRSDO1umWa8GbA4amoZXcdN5zk24HF2ItgxNUzE78xNLui%0A0JSHjNKrBnzqQAlpOCF%2BcGJ3SWmumnkBX2AiJYYANylJ2pQhgTEFjyTg1xe%2FbQID%0AAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCS6%2Fggvtq7lIKwzf7B9%2FMP8ns7fAK4H%2BgF%0AiakxCc%2BiAQlPEEyQ0z3hpAepbzsluke8Y76zu3%2F%2BCuomSXf7sB1XyF3sGgSKr%2BKF%0Ava4gm%2Bct9y%2BiP4VfOzyElulPnQxzxoK%2BviPGNVsxCWu4jXnXyPfJDuFutjBAyTxh%0ARgfDpUIukhZYOHN%2F5%2FtOxmF1yhK693OABMpp0mOXi2xcpxEoTYdywIt1tonJ2Yqg%0Aznc%2F0PjMlfubEkBkMTShZ35GdvfU%2F54I5yGsB37iOMi%2BoWs%2FJxKCjP86DUNi%2FfOf%0A0TLYBGZwxPlF%2BOiGwaquAi15xZdQD4HPHzKxF7MeAJ7rmJHDOyRSvsBKtAyU776a%0AwLIgavyfS%2B4%2B0H6uXjfAZH1a1IqUYVDrIVz6cYyEA5lWFDuN0H0r7cIhi7QA5Z6r%0ABEqiBeAPEbheNWJObv0tfdxEZytWnODDcHUVtqOjTSMBHoGbhmpvMnNsQY7eyzaF%0AdgsALyRfK30yCWJ66YKs%2B3cSP6KDPt1ZViPWgI5i91BtAasK%2F7YuVdNe2aHnPDtn%0AxC8ydqts2isrrd3T8lu897IARqPJAVBonwEJ3xOkfVzlTEIwVxycUnoXKk%2FyO5Td%0ANPFHBEvypV%2BQou2wnpmj2xyGaGWu0AL4itwHihDDWDiyU%2FkTzhyET9kO%2Fzjgt03c%0AEOJ3xkZLvA%3D%3D%0A-----END%20CERTIFICATE-----"
				dmsCert := "Hash=uftufy;Cert=\"" + cert + "\""

				csr, _ := GenerateCSR(rsaKey, "rsa", "Lamassu DMS Enroller")
				reqBody := bytes.NewBuffer(utils.EncodeB64(csr.Raw))

				e.POST("/.well-known/est/Lamassu DMS Enroller/serverkeygen").WithHeader("X-Forwarded-Client-Cert", dmsCert).WithHeader("Content-Type", "application/pkcs10").WithBytes([]byte(
					reqBody.Bytes())).
					Expect().
					Status(http.StatusInternalServerError)

			},
		},
		{
			name: "ServerKeyGen_ErrMissingAPS",
			serviceInitialization: func(s *service.Service) {
			},
			testRestEndpoint: func(s *httpexpect.Expect) {
			},

			testEstRestEndpoint: func(e *httpexpect.Expect) {

				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				cert := "-----BEGIN%20CERTIFICATE-----%0AMIIE4jCCAsqgAwIBAgIUYjFME%2Bs8jdOINAtFI5PsL7Ly41UwDQYJKoZIhvcNAQEL%0ABQAwNTEUMBIGA1UEChMLTGFtYXNzdSBQS0kxHTAbBgNVBAMTFExhbWFzc3UgRE1T%0AIEVucm9sbGVyMB4XDTIyMDUwNTEyMzA0NVoXDTQyMDQzMDEyMzExNVowTTEJMAcG%0AA1UEBhMAMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJMAcGA1UEChMAMQkwBwYDVQQL%0AEwAxFDASBgNVBAMTC0RlZmF1bHQtRE1TMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A%0AMIIBigKCAYEA21jRSekUsE3k9MgRmuzaT24zKyfQ007AJYA%2F62KcBkYuyUYDMjGJ%0AhECyAlhvafcMPbaCpa372eeH1icwPo8j8y1LCK21W3YhP4MGGvwjhX%2BI%2F48bGdM8%0AlRDYqlh0X%2Bf6NFWwY%2FMwGCXAEMgDNdUaMfHcYsXbJ79KTyL0lL55cVXk7dhzphCH%0AUL1bfn3Us9h7mqnMkfktPu%2BYFOAd%2Fays%2BSAPF0cC8U4IDpHMaV722ZGJIvjhWEPE%0AUYwwfBeW87cfVSop0tzPz8dem5%2B07ReenMCjtQ0lYrhKn%2FJySSAZh2nFoKmuvJsj%0ABOc%2FHehuF0NrLyGDU93Mm6V87%2FO%2FuX8oNsPRec9S4VNQWPoiVUbI5pHl8uVsDmmr%0Av%2FjkCq5eBLe5s0tan7Hl3hn5WANQ2Nuk4Uy1tJVD79tgX8811mjxxJ5oWAAlcUCC%0A%2FF2kaFgRJYDAWRnoren2lgJqWSSuF%2FYbUy2lfV0voWP%2FVUyDMgKMGtfcHXb4o29c%0APV11v%2FOqNit%2FAgMBAAGjUjBQMA4GA1UdDwEB%2FwQEAwIDqDAdBgNVHQ4EFgQUHhX3%0AsHqH4zgfqf3TKZp%2FD8qwcIAwHwYDVR0jBBgwFoAUFHB%2FZjp0NUI8bui7AB1vd4VB%0A%2FEgwDQYJKoZIhvcNAQELBQADggIBAFZGpZbktfnMEGsDaJ6ekQ%2FfdzD8hpgLNAKa%0AHw8hs3KAvCt%2B1C7o2rGbJqx7%2BU%2Fc9IJ4zWPD8KYA%2FbwYrgdKYzy1I7t8cJebeGS5%0Abc%2Fq0H0EWklzaLC9EIkFW7np2DxfwvNoO7r9e7Zn078YgzolcWs0laiOqAnkQqI2%0AXgwwnuOsCo0hV0CzXRReNKzmWOUSUTsQE%2Fi03I%2FJIvDOfoU5J7Mqi5Soj9fNYsJQ%0ATyJlheBVYfdHysRMQsW5z%2BCMmTpNU1FquTeDGhLn7D9cZT2nFOcTb%2Fs0ekaGr%2Fsy%0AFH9sxo%2BYCLs9W3sMRsKKqtQoth9Vw09MEIX%2BZMe1ULVms8DxtdH6cFa2FMW3XsSh%0AtqvW57u15GtbNZLAc8FNho1%2F6nrNMuWI5n2qQU56C7OLGE%2BiyYW8BKxNybLYGQyV%0As%2FDActKAKTYKhg%2F%2B20oipfXgqVd7KANWd7xPVFhxRE3UloZEmcHJo7MrkrPElofo%0A%2B5Pgz%2BLTKPgYhkbKilm4CQ3dFUsPEocMeWZNaBgC6MBndk6BNXTh05nUuLqbeCpS%0Aip0qthNg5H%2FKEZCKnq98t91huvQm0EAscXPfMAHrUEx0%2BSMQVY1HsMau%2BPJS6TQZ%0ASFonJFm6nYVDn3go%2FZu9VFaIJFkeuKBpSO43Gv6sc7plMJfuPV4LRi54EEdzFj1E%0Abj1P0LLm%0A-----END%20CERTIFICATE-----"
				//cert := "-----BEGIN%20CERTIFICATE-----%0AMIIFQzCCAysCFFqpO4cc1iGLIj1U1O11dIs9UVktMA0GCSqGSIb3DQEBCwUAMFwx%0ACzAJBgNVBAYTAkVTMREwDwYDVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNh%0AdGUxDDAKBgNVBAoMA0lLTDEMMAoGA1UECwwDWlBEMQswCQYDVQQDDAJDQTAeFw0y%0AMjAyMTYxMTUwMzdaFw0yMzAyMTExMTUwMzdaMGAxCzAJBgNVBAYTAkVTMREwDwYD%0AVQQIDAhHaXB1emtvYTERMA8GA1UEBwwIQXJyYXNhdGUxDDAKBgNVBAoMA0lLTDEM%0AMAoGA1UECwwDWlBEMQ8wDQYDVQQDDAZERVZJQ0UwggIiMA0GCSqGSIb3DQEBAQUA%0AA4ICDwAwggIKAoICAQC3lrywkgOu1H%2F6BnDc7NbTEaWSIVkdraRVtKIu2uz5np1O%0AwfBvtSR2N1hzYyZDleCmM4bg9%2F3rLztL7oUxqfjd1TRiTWXheJSBmxdZlhGewjww%0AbycmoGwkxAnlBWi7I0c7fNn6wZ%2Fo23H57%2BzqmpholfWyojU1oRIbSmo5DyKfA7P%2B%0A0VGvVRC5fC1qUzMA8RuDJQTcDeYN3dg6jjz2pkCRbWCCwoJflHRW6QnLQySsestH%0AOvZme1Xf3f3mPeTW0Yya2XWADNw60QueSslE0blrJfI710qWijp6zMJvF1nSC1gK%0AxJwOwzfxYsO%2FQV%2BJrD2zpIXg0JGEwzY8l8ZqZsFokwlDAC%2B9enI%2BgeRQIv6oB9Es%0Aug5c1fdLfR5tWvq1pVv6K7sIoUQ6p71zidXUBjheCnGjxyuyNXq3wKFnTzxAb7Cn%0Axrw84RPtCIMzYOc%2F4J4plBJjGEdh97vdJX5c42VWlQlS%2FvZFXCmpNHGUEBVgmn7T%0ABdHNn%2BhI2Z9s9xOYbD%2BDJh65KTGRUghOTv7ib2T2yzn%2Fa4nSUYZu1pioTtqwOvDH%0ASmhoaoXV%2Fgz2CqF7tVCRSDO1umWa8GbA4amoZXcdN5zk24HF2ItgxNUzE78xNLui%0A0JSHjNKrBnzqQAlpOCF%2BcGJ3SWmumnkBX2AiJYYANylJ2pQhgTEFjyTg1xe%2FbQID%0AAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCS6%2Fggvtq7lIKwzf7B9%2FMP8ns7fAK4H%2BgF%0AiakxCc%2BiAQlPEEyQ0z3hpAepbzsluke8Y76zu3%2F%2BCuomSXf7sB1XyF3sGgSKr%2BKF%0Ava4gm%2Bct9y%2BiP4VfOzyElulPnQxzxoK%2BviPGNVsxCWu4jXnXyPfJDuFutjBAyTxh%0ARgfDpUIukhZYOHN%2F5%2FtOxmF1yhK693OABMpp0mOXi2xcpxEoTYdywIt1tonJ2Yqg%0Aznc%2F0PjMlfubEkBkMTShZ35GdvfU%2F54I5yGsB37iOMi%2BoWs%2FJxKCjP86DUNi%2FfOf%0A0TLYBGZwxPlF%2BOiGwaquAi15xZdQD4HPHzKxF7MeAJ7rmJHDOyRSvsBKtAyU776a%0AwLIgavyfS%2B4%2B0H6uXjfAZH1a1IqUYVDrIVz6cYyEA5lWFDuN0H0r7cIhi7QA5Z6r%0ABEqiBeAPEbheNWJObv0tfdxEZytWnODDcHUVtqOjTSMBHoGbhmpvMnNsQY7eyzaF%0AdgsALyRfK30yCWJ66YKs%2B3cSP6KDPt1ZViPWgI5i91BtAasK%2F7YuVdNe2aHnPDtn%0AxC8ydqts2isrrd3T8lu897IARqPJAVBonwEJ3xOkfVzlTEIwVxycUnoXKk%2FyO5Td%0ANPFHBEvypV%2BQou2wnpmj2xyGaGWu0AL4itwHihDDWDiyU%2FkTzhyET9kO%2Fzjgt03c%0AEOJ3xkZLvA%3D%3D%0A-----END%20CERTIFICATE-----"

				dmsCert := "Hash=uftufy;Cert=\"" + cert + "\""

				csr, _ := GenerateCSR(rsaKey, "rsa", "Lamassu DMS Enroller")
				reqBody := bytes.NewBuffer(utils.EncodeB64(csr.Raw))

				e.POST("/.well-known/est//serverkeygen").WithHeader("X-Forwarded-Client-Cert", dmsCert).WithHeader("Content-Type", "application/pkcs10").WithBytes([]byte(
					reqBody.Bytes())).
					Expect().
					Status(http.StatusNotFound)

			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var logger log.Logger
			logger = log.NewJSONLogger(os.Stdout)
			logger = level.NewFilter(logger, level.AllowDebug())
			logger = log.With(logger, "ts", log.DefaultTimestampUTC)
			logger = log.With(logger, "caller", log.DefaultCaller)
			_, cfg := configs.NewConfig("")

			devicesDb, _ := mocks.NewDevicedDBMock(t)
			dmsDB, _ := mocks.NewDmsDBMock(t)
			statsDB, _ := devicesDB.NewInMemoryDB()

			tracer := opentracing.NoopTracer{}
			lamassuCaClient, _ := mocks.NewLamassuCaClientMock(logger)
			_, _ = lamassuCaClient.CreateCA(context.Background(), caDTO.Pki, "CA", caDTO.PrivateKeyMetadata{KeyType: "rsa", KeyBits: 2048}, caDTO.Subject{CommonName: "CA"}, 365*time.Hour, 30*time.Hour)
			s := service.NewDevicesService(devicesDb, statsDB, &lamassuCaClient, logger)

			verify := verify.NewUtils(&lamassuCaClient, logger)
			est := estserver.NewEstService(&lamassuCaClient, &verify, devicesDb, dmsDB, 2, logger)

			//Device-manager server initialization
			handler := MakeHTTPHandler(s, logger, tracer)
			server := httptest.NewServer(handler)
			defer server.Close()

			tc.serviceInitialization(&s)
			e := httpexpect.New(t, server.URL)
			tc.testRestEndpoint(e)

			//Est server initialization
			esthandler := estserver.MakeHTTPHandler(est, &lamassuCaClient, log.With(logger, "component", "HTTPS"), cfg, tracer, context.Background())
			estserver := httptest.NewServer(esthandler)
			defer estserver.Close()

			estE := httpexpect.New(t, estserver.URL)
			tc.testEstRestEndpoint(estE)
		})
	}
}

func GenerateCSR(key interface{}, Keytype string, caName string) (*x509.CertificateRequest, error) {
	subj := pkix.Name{
		Country:            []string{"ES"},
		Province:           []string{"Gipuzkoa"},
		Organization:       []string{"IKL"},
		OrganizationalUnit: []string{"ZPD"},
		Locality:           []string{"Arrasate"},
		CommonName:         caName,
	}
	if caName == "Lamassu DMS Enroller" {
		subj = pkix.Name{
			Country:            []string{""},
			Province:           []string{""},
			Organization:       []string{"Lamassu PKI"},
			OrganizationalUnit: []string{""},
			Locality:           []string{""},
			CommonName:         "Lamassu DMS Enroller",
		}
	}

	rawSubject := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubject)
	var template x509.CertificateRequest
	if Keytype == "rsa" {
		template = x509.CertificateRequest{
			RawSubject:         asn1Subj,
			SignatureAlgorithm: x509.SHA512WithRSA,
		}
	} else {
		template = x509.CertificateRequest{
			RawSubject:         asn1Subj,
			SignatureAlgorithm: x509.ECDSAWithSHA512,
		}
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csrNew, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %v", err)
	}
	return csrNew, nil
}
