package identityextractors

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

	// Parse the JWT
	tokenString := authToken[1]
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return
	}

	extractor.logger.Debugf("found JWT token in request headers")

	ctx.Set(string(IdentityExtractorJWT), token)
}
