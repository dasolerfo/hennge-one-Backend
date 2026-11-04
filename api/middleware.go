package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dasolerfo/hennge-one-Backend.git/token"
	"github.com/gin-gonic/gin"
)

const (
	authorizationHeaderKey  = "Authorization"
	authorizationTypeBearer = "bearer"
	AuthorizationPayloadKey = "authorization_payload"
)

// AuthMiddleware validates the bearer access token: it checks the RS256
// signature and expiration, and that the issuer matches this IdP.
func (server *Server) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		fields := strings.Fields(c.GetHeader(authorizationHeaderKey))
		if len(fields) != 2 || strings.ToLower(fields[0]) != authorizationTypeBearer {
			abortUnauthorized(c, "Missing or malformed Authorization header")
			return
		}

		payload, err := server.tokenMaker.VerifyAccessToken(fields[1])
		if err != nil {
			if errors.Is(err, token.ExpiredTokenError) {
				abortUnauthorized(c, "The access token has expired")
				return
			}
			abortUnauthorized(c, "Invalid access token signature")
			return
		}

		if payload.Issuer != server.Config.Issuer {
			abortUnauthorized(c, "The access token issuer is not trusted")
			return
		}

		c.Set(AuthorizationPayloadKey, payload)
		c.Next()
	}
}

func abortUnauthorized(c *gin.Context, description string) {
	c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":             "invalid_token",
		"error_description": description,
	})
}
