package identityextractors

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/sirupsen/logrus"
)

const (
	IdentityExtractorJWT IdentityExtractor = "JWT"
)

type JWTExtractor struct {
	logger *logrus.Entry
}

func (extractor JWTExtractor) ExtractAuthentication(ctx *gin.Context, req http.Request) {
	header := req.Header.Get("authorization")

	// The Authorization header typically looks like "Bearer <token>"
	authToken := strings.Split(header, " ")
	if len(authToken) != 2 || authToken[0] != "Bearer" {
		return
	}

	tokenString := authToken[1]
	claims, err := helpers.DecodeJWTPayload(tokenString)
	if err != nil {
		return
	}

	extractor.logger.Debugf("found JWT token in request headers")

	callerID, _ := claims["sub"].(string)

	ctx.Set(core.LamassuContextKeyAuthType, string(IdentityExtractorJWT))
	ctx.Set(core.LamassuContextKeyAuthCredentialString, tokenString)
	ctx.Set(core.LamassuContextKeyAuthCredentialStruct, claims)
	ctx.Set(core.LamassuContextKeyAuthID, callerID)
	ctx.Set(core.LamassuContextKeyAuthContext, claims)

	reqCtx := req.Context()
	reqCtx = context.WithValue(reqCtx, core.LamassuContextKeyAuthType, string(IdentityExtractorJWT))
	reqCtx = context.WithValue(reqCtx, core.LamassuContextKeyAuthCredentialString, tokenString)
	reqCtx = context.WithValue(reqCtx, core.LamassuContextKeyAuthCredentialStruct, claims)
	reqCtx = context.WithValue(reqCtx, core.LamassuContextKeyAuthID, callerID)
	reqCtx = context.WithValue(reqCtx, core.LamassuContextKeyAuthContext, claims)
	if ctx.Request != nil {
		ctx.Request = ctx.Request.WithContext(reqCtx)
	}
}
