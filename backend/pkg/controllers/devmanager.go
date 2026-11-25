package controllers

import (
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
)

const (
	// sseKeepaliveInterval is how often an idle SSE stream gets a comment line, so proxies do not close it.
	sseKeepaliveInterval = 15 * time.Second
	// sseWriteWindow is how long a single SSE write may block before the stream is ended.
	sseWriteWindow = 30 * time.Second
	// sseRetryAfterSeconds is the Retry-After value sent when the subscriber limit is reached.
	sseRetryAfterSeconds = "10"
)

type devManagerHttpRoutes struct {
	svc    services.DeviceManagerService
	sseHub *DeviceEventSSEHub

	sseKeepaliveInterval time.Duration
	sseWriteWindow       time.Duration
	sseMaxStreamDuration time.Duration
}

func NewDeviceManagerHttpRoutes(svc services.DeviceManagerService) *devManagerHttpRoutes {
	return &devManagerHttpRoutes{
		svc: svc,
	}
}

func NewDeviceManagerHttpRoutesWithSSE(svc services.DeviceManagerService, hub *DeviceEventSSEHub) *devManagerHttpRoutes {
	r := &devManagerHttpRoutes{
		svc:                  svc,
		sseHub:               hub,
		sseKeepaliveInterval: sseKeepaliveInterval,
		sseWriteWindow:       sseWriteWindow,
	}
	if hub != nil {
		r.sseMaxStreamDuration = hub.MaxStreamDuration()
	}
	return r
}

func (r *devManagerHttpRoutes) GetStats(ctx *gin.Context) {
	queryParams, err := FilterQuery(ctx.Request, resources.DeviceFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	stats, err := r.svc.GetDevicesStats(ctx.Request.Context(), services.GetDevicesStatsInput{
		QueryParameters: queryParams,
	})

	if err != nil {
		switch err {
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.JSON(200, stats)
}

func (r *devManagerHttpRoutes) GetAllDevices(ctx *gin.Context) {
	queryParams, err := FilterQuery(ctx.Request, resources.DeviceFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	devices := []models.Device{}
	nextBookmark, err := r.svc.GetDevices(ctx.Request.Context(), services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, resources.GetDevicesResponse{
		IterableList: resources.IterableList[models.Device]{
			NextBookmark: nextBookmark,
			List:         devices,
		},
	})
}

func (r *devManagerHttpRoutes) GetDevicesByDMS(ctx *gin.Context) {
	queryParams, err := FilterQuery(ctx.Request, resources.DeviceFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}
	type uriParams struct {
		DMSID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	devices := []models.Device{}
	nextBookmark, err := r.svc.GetDeviceByDMS(ctx.Request.Context(), services.GetDevicesByDMSInput{
		DMSID: params.DMSID,
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, resources.GetDevicesResponse{
		IterableList: resources.IterableList[models.Device]{
			NextBookmark: nextBookmark,
			List:         devices,
		},
	})
}

func (r *devManagerHttpRoutes) GetDeviceByID(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dms, err := r.svc.GetDeviceByID(ctx.Request.Context(), services.GetDeviceByIDInput{
		ID: params.ID,
	})
	if err != nil {
		switch err {
		case errs.ErrDeviceNotFound:
			ctx.JSON(400, gin.H{"err": err.Error()})
			return
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
			return
		}
	}

	ctx.JSON(200, dms)
}

func (r *devManagerHttpRoutes) GetDeviceEvents(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	// Content negotiation: if the client requests SSE, stream events in real time.
	// Match any Accept header that includes text/event-stream (e.g. "text/event-stream, */*;q=0.5").
	// RFC 7231 declares media types case-insensitive, so normalize before matching.
	if strings.Contains(strings.ToLower(ctx.GetHeader("Accept")), "text/event-stream") {
		r.streamDeviceEventsSSE(ctx, params.ID)
		return
	}

	queryParams, err := FilterQuery(ctx.Request, resources.DeviceEventFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	events := []models.DeviceEvent{}
	nextBookmark, err := r.svc.GetDeviceEvents(ctx.Request.Context(), services.GetDeviceEventsInput{
		DeviceID: params.ID,
		ListInput: resources.ListInput[models.DeviceEvent]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(ev models.DeviceEvent) {
				events = append(events, ev)
			},
		},
	})
	if err != nil {
		switch err {
		case errs.ErrDeviceNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.JSON(200, resources.GetDeviceEventsResponse{
		IterableList: resources.IterableList[models.DeviceEvent]{
			NextBookmark: nextBookmark,
			List:         events,
		},
	})
}

func (r *devManagerHttpRoutes) CreateDeviceEvent(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.CreateDeviceEventBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	// Normalize Source attribution.
	//
	// Priority: body > x-lms-source header > "api/external".
	//
	// Internal SDK clients (DMS Manager, CA, etc.) inject an x-lms-source
	// header via sdk.HttpClientWithSourceHeaderInjector but leave the body
	// field empty, so the header acts as the fallback for service-attributed
	// events. Callers that provide an explicit source in the body bypass the
	// header entirely.
	source := requestBody.Source
	if source == "" {
		if ctx.GetHeader(models.HttpSourceHeader) != "" {
			source = ctx.GetHeader(models.HttpSourceHeader)
		} else {
			source = "api/external"
		}
	}

	// Normalize Timestamp: default to now; reject timestamps more than 5
	// minutes in the future to prevent forging future events.
	ts := requestBody.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	} else if ts.After(time.Now().Add(5 * time.Minute)) {
		ctx.JSON(400, gin.H{"err": "timestamp cannot be more than 5 minutes in the future"})
		return
	}

	event, err := r.svc.CreateDeviceEvent(ctx.Request.Context(), services.CreateDeviceEventInput{
		DeviceID:         params.ID,
		Timestamp:        ts,
		Type:             requestBody.Type,
		Description:      requestBody.Description,
		Source:           source,
		StructuredFields: requestBody.StructuredFields,
	})
	if err != nil {
		switch err {
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrDeviceNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.JSON(201, event)
}

func (r *devManagerHttpRoutes) CreateDevice(ctx *gin.Context) {
	var requestBody resources.CreateDeviceBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dev, err := r.svc.CreateDevice(ctx.Request.Context(), services.CreateDeviceInput{
		ID:        requestBody.ID,
		Alias:     requestBody.Alias,
		Tags:      requestBody.Tags,
		Metadata:  requestBody.Metadata,
		Icon:      requestBody.Icon,
		IconColor: requestBody.IconColor,
		DMSID:     requestBody.DMSID,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(201, dev)
}

func (r *devManagerHttpRoutes) UpdateDeviceIdentitySlot(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateDeviceIdentitySlotBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dev, err := r.svc.UpdateDeviceIdentitySlot(ctx.Request.Context(), services.UpdateDeviceIdentitySlotInput{
		ID:   params.ID,
		Slot: requestBody.Slot,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, dev)
}

func (r *devManagerHttpRoutes) UpdateDeviceMetadata(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateDeviceMetadataBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dev, err := r.svc.UpdateDeviceMetadata(ctx.Request.Context(), services.UpdateDeviceMetadataInput{
		ID:      params.ID,
		Patches: requestBody.Patches,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, dev)
}

func (r *devManagerHttpRoutes) DecommissionDevice(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dev, err := r.svc.UpdateDeviceStatus(ctx.Request.Context(), services.UpdateDeviceStatusInput{
		ID:        params.ID,
		NewStatus: models.DeviceDecommissioned,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, dev)
}

func (r *devManagerHttpRoutes) DeleteDevice(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	err := r.svc.DeleteDevice(ctx.Request.Context(), services.DeleteDeviceInput{
		ID: params.ID,
	})

	if err != nil {
		switch err {
		case errs.ErrDeviceNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrDeviceInvalidStatus:
			ctx.JSON(422, gin.H{"err": err.Error()}) // Unprocessable Entity for invalid state
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.Status(204) // No Content for successful deletion
}

// ============================================================================
// Device Group Operations
// ============================================================================

func (r *devManagerHttpRoutes) CreateDeviceGroup(ctx *gin.Context) {
	var requestBody resources.CreateDeviceGroupBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	// Convert API request criteria (with operand names) to model criteria (with FilterOperation enums)
	modelCriteria, err := ConvertDeviceGroupCriteria(requestBody.Criteria, resources.DeviceFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	group, err := r.svc.CreateDeviceGroup(ctx.Request.Context(), services.CreateDeviceGroupInput{
		ID:          requestBody.ID,
		Name:        requestBody.Name,
		Description: requestBody.Description,
		ParentID:    requestBody.ParentID,
		Criteria:    modelCriteria,
	})

	if err != nil {
		switch err {
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrDeviceGroupCircularReference:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrDeviceGroupNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	// Convert operands from integers to names for API response
	responseGroup := ConvertDeviceGroupToResponse(group, group.OwnCriteriaCount)

	ctx.JSON(201, responseGroup)
}

func (r *devManagerHttpRoutes) UpdateDeviceGroup(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	var requestBody resources.UpdateDeviceGroupBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	// Convert API request criteria (with operand names) to model criteria (with FilterOperation enums)
	modelCriteria, err := ConvertDeviceGroupCriteria(requestBody.Criteria, resources.DeviceFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	group, err := r.svc.UpdateDeviceGroup(ctx.Request.Context(), services.UpdateDeviceGroupInput{
		ID:          params.ID,
		Name:        requestBody.Name,
		Description: requestBody.Description,
		ParentID:    requestBody.ParentID,
		Criteria:    modelCriteria,
	})

	if err != nil {
		switch err {
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrDeviceGroupCircularReference:
			ctx.JSON(400, gin.H{"err": err.Error()})
		case errs.ErrDeviceGroupNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	// Convert operands from integers to names for API response
	responseGroup := ConvertDeviceGroupToResponse(group, group.OwnCriteriaCount)

	ctx.JSON(200, responseGroup)
}

func (r *devManagerHttpRoutes) DeleteDeviceGroup(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	err := r.svc.DeleteDeviceGroup(ctx.Request.Context(), services.DeleteDeviceGroupInput{
		ID: params.ID,
	})

	if err != nil {
		switch err {
		case errs.ErrDeviceGroupNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		case errs.ErrValidateBadRequest:
			ctx.JSON(400, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.Status(204) // No Content for successful deletion
}

func (r *devManagerHttpRoutes) GetDeviceGroupByID(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	group, err := r.svc.GetDeviceGroupByID(ctx.Request.Context(), services.GetDeviceGroupByIDInput{
		ID: params.ID,
	})

	if err != nil {
		switch err {
		case errs.ErrDeviceGroupNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	// Convert operands from integers to names for API response
	responseGroup := ConvertDeviceGroupToResponse(group, group.OwnCriteriaCount)

	ctx.JSON(200, responseGroup)
}

func (r *devManagerHttpRoutes) GetAllDeviceGroups(ctx *gin.Context) {
	queryParams, err := FilterQuery(ctx.Request, resources.DeviceFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	groups := []models.DeviceGroup{}
	nextBookmark, err := r.svc.GetDeviceGroups(ctx.Request.Context(), services.GetDeviceGroupsInput{
		ListInput: resources.ListInput[models.DeviceGroup]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(group models.DeviceGroup) {
				groups = append(groups, group)
			},
		},
	})

	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	// Convert groups to response format with operand names
	responseGroups := make([]map[string]any, len(groups))
	for i, group := range groups {
		responseGroups[i] = ConvertDeviceGroupToResponse(&group, group.OwnCriteriaCount)
	}

	ctx.JSON(200, gin.H{
		"next_bookmark": nextBookmark,
		"list":          responseGroups,
	})
}

func (r *devManagerHttpRoutes) GetDevicesByGroup(ctx *gin.Context) {
	type uriParams struct {
		GroupID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	queryParams, err := FilterQuery(ctx.Request, resources.DeviceFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	devices := []models.Device{}
	nextBookmark, err := r.svc.GetDevicesByGroup(ctx.Request.Context(), services.GetDevicesByGroupInput{
		GroupID: params.GroupID,
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(dev models.Device) {
				devices = append(devices, dev)
			},
		},
	})

	if err != nil {
		switch err {
		case errs.ErrDeviceGroupNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.JSON(200, resources.GetDevicesResponse{
		IterableList: resources.IterableList[models.Device]{
			NextBookmark: nextBookmark,
			List:         devices,
		},
	})
}

func (r *devManagerHttpRoutes) GetDeviceGroupStats(ctx *gin.Context) {
	type uriParams struct {
		GroupID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	stats, err := r.svc.GetDeviceGroupStats(ctx.Request.Context(), services.GetDeviceGroupStatsInput{
		GroupID: params.GroupID,
	})

	if err != nil {
		switch err {
		case errs.ErrDeviceGroupNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.JSON(200, stats)
}

// streamDeviceEventsSSE handles the SSE streaming path for GetDeviceEvents.
// Called when the client sends Accept: text/event-stream.
//
// The stream outlives the HTTP server's WriteTimeout: before every write the handler moves the write
// deadline to now + sseWriteWindow, so a client that stops reading ends the stream after that window instead of
// pinning a goroutine and a hub slot. The stream is closed after sseMaxStreamDuration (plus jitter) so that
// permission changes are picked up when the client reconnects.
func (r *devManagerHttpRoutes) streamDeviceEventsSSE(ctx *gin.Context, deviceID string) {
	if r.sseHub == nil {
		ctx.JSON(501, gin.H{"err": "SSE is disabled by configuration or not supported in this deployment"})
		return
	}

	// Subscribe before the lookup so a refused request costs no database call; the deferred Unsubscribe
	// releases the slot if the lookup fails.
	ch, err := r.sseHub.Subscribe(deviceID)
	if err != nil {
		if errors.Is(err, ErrSSESubscriberLimit) {
			ctx.Header("Retry-After", sseRetryAfterSeconds)
		}
		ctx.JSON(503, gin.H{"err": err.Error()})
		return
	}
	defer r.sseHub.Unsubscribe(deviceID, ch)

	// Verify device exists
	_, err = r.svc.GetDeviceByID(ctx.Request.Context(), services.GetDeviceByIDInput{
		ID: deviceID,
	})
	if err != nil {
		switch err {
		case errs.ErrDeviceNotFound:
			ctx.JSON(404, gin.H{"err": err.Error()})
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}
		return
	}

	ctx.Header("Content-Type", "text/event-stream")
	ctx.Header("Cache-Control", "no-cache")
	ctx.Header("Connection", "keep-alive")
	ctx.Header("X-Accel-Buffering", "no")

	rc := http.NewResponseController(ctx.Writer)
	deadlineWarned := false
	// send writes one frame under a fresh write deadline. The flush error is not checked: gin's writer
	// implements http.Flusher without an error, so a failed flush shows up on the next write instead.
	send := func(frame string) error {
		if err := rc.SetWriteDeadline(time.Now().Add(r.sseWriteWindow)); err != nil && !deadlineWarned {
			deadlineWarned = true
			r.sseHub.logger.Warnf("SSE stream for device %s: cannot set write deadline: %s", deviceID, err)
		}
		if _, err := io.WriteString(ctx.Writer, frame); err != nil {
			return err
		}
		ctx.Writer.Flush()
		return nil
	}

	// Flush headers immediately so the client sees the SSE connection is open
	if err := send(""); err != nil {
		return
	}

	// Keepalive comments stop proxies and load balancers from closing an idle stream.
	keepalive := time.NewTicker(r.sseKeepaliveInterval)
	defer keepalive.Stop()

	// Jitter keeps streams opened together (for example after a deploy) from all reconnecting at once.
	lifetime := time.NewTimer(r.sseMaxStreamDuration + rand.N(r.sseMaxStreamDuration/10+1))
	defer lifetime.Stop()

	clientGone := ctx.Request.Context().Done()
	for {
		select {
		case <-clientGone:
			return
		case <-lifetime.C:
			// The terminating chunk is written after we return, under the deadline of the last write, which
			// may be a whole keepalive interval old. Renew it so a clean close does not depend on keepalive < window.
			_ = rc.SetWriteDeadline(time.Now().Add(r.sseWriteWindow))
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			// SSE data frame
			if err := send("event: device-event\ndata: " + data + "\n\n"); err != nil {
				return
			}
		case <-keepalive.C:
			// SSE comment line — keeps the connection alive without triggering client events
			if err := send(": keepalive\n\n"); err != nil {
				return
			}
		}
	}
}
