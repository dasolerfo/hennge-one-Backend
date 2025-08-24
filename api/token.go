package api

import (
	"github.com/gin-gonic/gin"
)

func TokenGetHandler(c *gin.Context) {

}

type TokenPostHandlerRequest struct {
	GrantType   string `form:"grant_type" binding:"required"`
	ClientID    string `form:"client_id" binding:"required"`
	RedirectUri string `form:"redirect_uri" binding:"required"`
	Code        string `form:"code" binding:"required"`
}
type TokenPostHandlerResponse struct {
	AccessToken  string `json:"access_token"`
	TockenType   string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IdToken      string `json:"id_token"`
}

func (server *Server) TokenPostHandler(c *gin.Context) {
	var req TokenPostHandlerRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Bad request has been made, please check the parameters",
		})
		return
	}
	authCode, err := server.store.GetAuthCode(c.Request.Context(), req.Code)
	if err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code or expired",
		})
		return
	}
	if authCode.ClientID != req.ClientID {
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "The client ID does not match the one used in the authorization request",
		})
		return
	}
	if req.RedirectUri != "" && authCode.RedirectUri != req.RedirectUri {
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "The redirect URI does not match with the one used in the authorization request",
		})
		return
	}
	if authCode.Scope.String != "openid" {
		c.JSON(400, gin.H{
			"error":             "invalid_scope",
			"error_description": "The scope is not valid",
		})
		return
	}

	idtoken, payload, err := server.tokenMaker.CreateIDToken(req.ClientID, authCode.Sub, []string{req.ClientID}, server.Config.TokenDuration)
	accessToken, _, err := server.tokenMaker.CreateToken(authCode.Sub, server.Config.TokenDuration)

	response := &TokenPostHandlerResponse{
		IdToken:     idtoken,
		ExpiresIn:   payload.ExpiredAt,
		TockenType:  "Bearer",
		AccessToken: accessToken,
	}

	c.JSON(200, response)
	return

}
