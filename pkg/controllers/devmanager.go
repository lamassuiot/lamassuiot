package controllers

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/routes/middlewares/sse"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

type devManagerHttpRoutes struct {
	svc    services.DeviceManagerService
	stream *sse.Event
}

func NewDeviceManagerHttpRoutes(svc services.DeviceManagerService, eventStream *sse.Event) *devManagerHttpRoutes {
	return &devManagerHttpRoutes{
		svc:    svc,
		stream: eventStream,
	}
}

func (r *devManagerHttpRoutes) GetStats(ctx *gin.Context) {
	stats, err := r.svc.GetDevicesStats(ctx, services.GetDevicesStatsInput{})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, stats)
}

func (r *devManagerHttpRoutes) GetAllDevices(ctx *gin.Context) {
	queryParams := FilterQuery(ctx.Request, resources.DeviceFiltrableFields)

	devices := []models.Device{}
	nextBookmark, err := r.svc.GetDevices(ctx, services.GetDevicesInput{
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
	queryParams := FilterQuery(ctx.Request, resources.DeviceFiltrableFields)
	type uriParams struct {
		DMSID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	devices := []models.Device{}
	nextBookmark, err := r.svc.GetDeviceByDMS(ctx, services.GetDevicesByDMSInput{
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

	dms, err := r.svc.GetDeviceByID(ctx, services.GetDeviceByIDInput{
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

func (r *devManagerHttpRoutes) CreateDevice(ctx *gin.Context) {
	var requestBody resources.CreateDeviceBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	dev, err := r.svc.CreateDevice(ctx, services.CreateDeviceInput{
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

	dev, err := r.svc.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{
		ID:        params.ID,
		Slot:      requestBody.Slot,
		NewStatus: requestBody.NewStatus,
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

	dev, err := r.svc.UpdateDeviceMetadata(ctx, services.UpdateDeviceMetadataInput{
		ID:       params.ID,
		Metadata: requestBody.Metadata,
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

	dev, err := r.svc.UpdateDeviceStatus(ctx, services.UpdateDeviceStatusInput{
		ID:        params.ID,
		NewStatus: models.DeviceDecommissioned,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(200, dev)
}

func (r *devManagerHttpRoutes) GetDeviceEventsInStream(ctx *gin.Context) {
	type uriParams struct {
		ID string `uri:"id" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	queryParams := FilterQuery(ctx.Request, resources.DeviceFiltrableFields)

	v, ok := ctx.Get("client")
	if !ok {
		ctx.JSON(500, nil)
		return
	}

	client, ok := v.(sse.Client)
	if !ok {
		ctx.JSON(500, nil)
		return
	}

	// This goroutine will send the above data to Message channel
	// Which will pass through listen(), where it will get sent to the specified client (To)
	var lastTs *time.Time
	go func() {
		t := time.NewTicker(time.Second * 3)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if r.stream.TotalClients[client.ID] == nil {
					// Client doesn't exist or disconnected
					log.Printf("Receiver - %d doesn't exist or disconnected.", 1)
					// return
				} else {
					events := []models.DeviceEvent{}
					now := time.Now()
					ts := now
					if lastTs != nil {
						ts = *lastTs
					}

					fmt.Println(ts.Format(time.DateTime))

					queryParams.Filters = append(queryParams.Filters, resources.FilterOption{
						Field:           "timestamp",
						FilterOperation: resources.DateAfter,
						Value:           fmt.Sprintf("%s.%d", ts.Format(time.DateTime), ts.Nanosecond()/1000000),
					})

					_, err := r.svc.GetDeviceEvents(ctx, services.GetDeviceEventsInput{
						DeviceID: params.ID,
						ListInput: resources.ListInput[models.DeviceEvent]{
							QueryParameters: queryParams,
							ExhaustiveRun:   false,
							ApplyFunc: func(event models.DeviceEvent) {
								events = append(events, event)
							},
						},
					})
					if err != nil {
						log.Printf("Error getting events: %s", err)
						return
					}

					lastTs = &now

					// Data to be sent to a specific client
					// Currently this data would be sent to the first client on every new connection
					data := sse.Data{
						Message: events,
						From:    client.ID,
						To:      client.ID, // To send this data to a specified client, you can change this to the specific client ID
					}

					r.stream.Message <- data
				}
			}
		}
	}()

	ctx.Stream(func(w io.Writer) bool {
		// Stream data to client
		for {
			select {
			// Send msg to the client
			case msg, ok := <-client.Channel:
				if !ok {
					return false
				}
				ctx.SSEvent("message", msg)
				return true
			// Client exit
			case <-ctx.Request.Context().Done():
				log.Printf("Client %d disconnected", client.ID)
				return false
			}
		}
	})
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

	queryParams := FilterQuery(ctx.Request, resources.DeviceFiltrableFields)
	events := []models.DeviceEvent{}
	nextBookmark, err := r.svc.GetDeviceEvents(ctx, services.GetDeviceEventsInput{
		DeviceID: params.ID,
		ListInput: resources.ListInput[models.DeviceEvent]{
			QueryParameters: queryParams,
			ExhaustiveRun:   false,
			ApplyFunc: func(event models.DeviceEvent) {
				events = append(events, event)
			},
		},
	})

	if err != nil {
		ctx.JSON(500, err)
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

	event, err := r.svc.CreateDeviceEvent(ctx, services.CreateDeviceEventInput{
		DeviceID:         params.ID,
		Timestamp:        requestBody.Timestamp,
		Type:             requestBody.Type,
		Description:      requestBody.Description,
		Source:           requestBody.Source,
		Status:           requestBody.Status,
		StructuredFields: requestBody.StructuredFields,
	})

	if err != nil {
		ctx.JSON(500, err)
		return
	}

	ctx.JSON(201, event)
}
