package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	cresources "github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type alertsHttpRoutes struct {
	svc services.AlertsService
}

func NewAlertsHttpRoutes(svc services.AlertsService) *alertsHttpRoutes {
	return &alertsHttpRoutes{
		svc: svc,
	}
}

func (r *alertsHttpRoutes) GetUserSubscriptions(ctx *gin.Context) {
	type uriParams struct {
		UserID string `uri:"userId" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	response, err := r.svc.GetUserSubscriptions(ctx.Request.Context(), &services.GetUserSubscriptionsInput{
		UserID: params.UserID,
	})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, response)
}

func (r *alertsHttpRoutes) GetLatestEventsPerEventType(ctx *gin.Context) {
	response, err := r.svc.GetLatestEventsPerEventType(ctx.Request.Context(), &services.GetLatestEventsPerEventTypeInput{})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, response)
}

func (r *alertsHttpRoutes) Subscribe(ctx *gin.Context) {
	var requestBody resources.SubscribeBody
	if err := ctx.BindJSON(&requestBody); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	type uriParams struct {
		UserID string `uri:"userId" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	response, err := r.svc.Subscribe(ctx.Request.Context(), &services.SubscribeInput{
		UserID:     params.UserID,
		EventType:  requestBody.EventType,
		Conditions: requestBody.Conditions,
		Channel:    requestBody.Channel,
	})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, response)
}

func (r *alertsHttpRoutes) Unsubscribe(ctx *gin.Context) {
	type uriParams struct {
		UserID         string `uri:"userId" binding:"required"`
		SubscriptionID string `uri:"subId" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	response, err := r.svc.Unsubscribe(ctx.Request.Context(), &services.UnsubscribeInput{
		UserID:         params.UserID,
		SubscriptionID: params.SubscriptionID,
	})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, response)
}

func (r *alertsHttpRoutes) GetEvents(ctx *gin.Context) {
	queryParams, err := FilterQuery(ctx.Request, cresources.StoredEventFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	events := []models.StoredEvent{}
	nextBookmark, err := r.svc.GetEvents(ctx.Request.Context(), &services.GetEventsInput{
		QueryParameters: queryParams,
		ExhaustiveRun:   false,
		ApplyFunc: func(ev models.StoredEvent) {
			events = append(events, ev)
		},
	})

	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, cresources.GetItemsResponse[models.StoredEvent]{
		IterableList: cresources.IterableList[models.StoredEvent]{
			NextBookmark: nextBookmark,
			List:         events,
		},
	})
}

func (r *alertsHttpRoutes) GetEventByID(ctx *gin.Context) {
	type uriParams struct {
		EventID string `uri:"eventId" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ev, err := r.svc.GetEventByID(ctx.Request.Context(), &services.GetEventByIDInput{ID: params.EventID})
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	if ev == nil {
		ctx.JSON(404, gin.H{"err": "event not found"})
		return
	}

	ctx.JSON(200, ev)
}

func (r *alertsHttpRoutes) GetEventRetentionSettings(ctx *gin.Context) {
	settings, err := r.svc.GetEventRetentionSettings(ctx.Request.Context())
	if err != nil {
		ctx.JSON(500, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, settings)
}

func (r *alertsHttpRoutes) UpdateEventRetentionSettings(ctx *gin.Context) {
	var body services.UpdateEventRetentionSettingsInput
	if err := ctx.BindJSON(&body); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	settings, err := r.svc.UpdateEventRetentionSettings(ctx.Request.Context(), &body)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	ctx.JSON(200, settings)
}
