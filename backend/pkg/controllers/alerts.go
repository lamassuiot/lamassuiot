package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type AlertsHttpRoutes interface {
	GetUserSubscriptions(ctx *gin.Context)
	GetLatestEventsPerEventType(ctx *gin.Context)
	Subscribe(ctx *gin.Context)
	Unsubscribe(ctx *gin.Context)
}

type backendAlertsHttpRoutes struct {
	svc services.AlertsService
}

func NewBackendAlertsHttpRoutes(svc services.AlertsService) *backendAlertsHttpRoutes {
	return &backendAlertsHttpRoutes{
		svc: svc,
	}
}

func (r *backendAlertsHttpRoutes) GetUserSubscriptions(ctx *gin.Context) {
	type uriParams struct {
		UserID string `uri:"userId" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	response, err := r.svc.GetUserSubscriptions(ctx, &services.GetUserSubscriptionsInput{
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

func (r *backendAlertsHttpRoutes) GetLatestEventsPerEventType(ctx *gin.Context) {
	response, err := r.svc.GetLatestEventsPerEventType(ctx, &services.GetLatestEventsPerEventTypeInput{})

	if err != nil {
		switch err {
		default:
			ctx.JSON(500, gin.H{"err": err.Error()})
		}

		return
	}

	ctx.JSON(200, response)
}

func (r *backendAlertsHttpRoutes) Subscribe(ctx *gin.Context) {
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

	response, err := r.svc.Subscribe(ctx, &services.SubscribeInput{
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

func (r *backendAlertsHttpRoutes) Unsubscribe(ctx *gin.Context) {
	type uriParams struct {
		UserID         string `uri:"userId" binding:"required"`
		SubscriptionID string `uri:"subId" binding:"required"`
	}

	var params uriParams
	if err := ctx.ShouldBindUri(&params); err != nil {
		ctx.JSON(400, gin.H{"err": err.Error()})
		return
	}

	response, err := r.svc.Unsubscribe(ctx, &services.UnsubscribeInput{
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
