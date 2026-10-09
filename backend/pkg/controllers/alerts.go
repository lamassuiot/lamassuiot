package controllers

import (
	"github.com/gin-gonic/gin"
	backendresources "github.com/lamassuiot/lamassuiot/backend/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
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
	queryParams, err := FilterQuery(ctx.Request, resources.AlertFilterableFields)
	if err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	events := []models.AlertLatestEvent{}
	nextBookmark, err := r.svc.GetLatestEventsPerEventType(ctx.Request.Context(), &services.GetLatestEventsPerEventTypeInput{
		QueryParameters: queryParams,
		ExhaustiveRun:   false,
		ApplyFunc: func(ev models.AlertLatestEvent) {
			events = append(events, ev)
		},
	})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, resources.GetAlertsResponse{
		IterableList: resources.IterableList[models.AlertLatestEvent]{
			NextBookmark: nextBookmark,
			List:         events,
		},
	})
}

func (r *alertsHttpRoutes) Subscribe(ctx *gin.Context) {
	var requestBody backendresources.SubscribeBody
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
