package api

import (
	"net/url"
	"strconv"

	"github.com/gin-gonic/gin"
)

func TokenGetHandler(c *gin.Context) {

}

type TokenPostHandlerRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	ClientID     int64  `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret" binding:"required"`
	RedirectUri  string `form:"redirect_uri" binding:"required"`
	Code         string `form:"code" binding:"required"`
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
	client, err := server.store.GetClientByID(c.Request.Context(), req.ClientID)
	if err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_client",
			"error_description": "The client ID is invalid",
		})
		return
	} else if client.ClientSecret != req.ClientSecret {
		c.JSON(400, gin.H{
			"error":             "invalid_client",
			"error_description": "The client secret is invalid",
		})
		return
	}
	parsedRedirectUri, err := url.QueryUnescape(req.RedirectUri)

	if err != nil || parsedRedirectUri == "" {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "The redirect URI is not valid",
		})
		return
	}

	if req.RedirectUri != "" && authCode.RedirectUri != parsedRedirectUri {
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
	stringClientID := strconv.FormatInt(req.ClientID, 10)

	idtoken, payload, err := server.tokenMaker.CreateIDToken(server.Config.Issuer, authCode.Sub, []string{stringClientID}, authCode.CreatedAt.Unix(), server.Config.TokenDuration)
	userId, err := strconv.ParseInt(authCode.Sub, 10, 64)
	//TODO: millorar això
	user, err := server.store.GetUserByID(c.Request.Context(), userId)

	if err != nil {
		c.JSON(500, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
		return
	}
	accessToken, _, err := server.tokenMaker.CreateToken(user.Email, server.Config.TokenDuration)

	response := &TokenPostHandlerResponse{
		IdToken:     idtoken,
		ExpiresIn:   payload.ExpiredAt,
		TockenType:  "Bearer",
		AccessToken: accessToken,
	}

	c.JSON(200, response)
	return

}
