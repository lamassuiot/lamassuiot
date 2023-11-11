package controllers

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
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

	funCtx := helpers.ConfigureContextWithRequest(context.Background(), ctx.Request.Header)

	response, err := r.svc.GetUserSubscriptions(funCtx, &services.GetUserSubscriptionsInput{
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
	funCtx := helpers.ConfigureContextWithRequest(context.Background(), ctx.Request.Header)

	response, err := r.svc.GetLatestEventsPerEventType(funCtx, &services.GetLatestEventsPerEventTypeInput{})

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

	funCtx := helpers.ConfigureContextWithRequest(context.Background(), ctx.Request.Header)

	response, err := r.svc.Subscribe(funCtx, &services.SubscribeInput{
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

	funCtx := helpers.ConfigureContextWithRequest(context.Background(), ctx.Request.Header)

	response, err := r.svc.Unsubscribe(funCtx, &services.UnsubscribeInput{
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
