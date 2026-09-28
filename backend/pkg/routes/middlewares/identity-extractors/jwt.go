package identityextractors

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

const (
	IdentityExtractorJWT IdentityExtractor = "JWT"
)

type JWTExtractor struct {
	logger    *logrus.Entry
	validator *JWTValidator
}

func (extractor JWTExtractor) ExtractAuthentication(ctx *gin.Context, req http.Request) {
	header := req.Header.Get("authorization")

	// The Authorization header typically looks like "Bearer <token>"
	authToken := strings.Fields(header)
	if len(authToken) != 2 || !strings.EqualFold(authToken[0], "Bearer") || extractor.validator == nil {
		return
	}

	tokenString := authToken[1]
	token, err := extractor.validator.Validate(tokenString)
	if err != nil {
		extractor.logger.WithError(err).Debug("rejecting invalid bearer token")
		return
	}

	extractor.logger.Debug("validated bearer token")
	ctx.Set(string(IdentityExtractorJWT), token)
}
