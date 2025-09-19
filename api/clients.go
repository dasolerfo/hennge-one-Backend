package api

import (
	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/gin-gonic/gin"
)

type ClientRegisterRequest struct {
	ClientID     string   `json:"client_id" binding:"required"`
	ClientName   string   `json:"client_name" binding:"required"`
	ClientSecret string   `json:"client_secret" binding:"required"`
	RedirectUris []string `json:"redirect_uris" binding:"required"`
}

func (server *Server) RegisterClientHandler(c *gin.Context) {
	var req ClientRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Bad request has been made, please check the parameters",
		})
		return
	}
	_, err := server.store.GetClientByID(c.Request.Context(), req.ClientID)
	if err == nil {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Client ID already exists",
		})
		return
	}

	client, err := server.store.CreateClient(c.Request.Context(), db.CreateClientParams{
		ID:           req.ClientID,
		ClientName:   req.ClientName,
		ClientSecret: req.ClientSecret,
		RedirectUris: req.RedirectUris,
	})
	if err != nil {
		c.JSON(500, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "Client registered successfully!",
		"response": gin.H{
			"client_id":   client.ID,
			"client_name": client.ClientName,
		},
	})
	return
}

type ClientsGetHandlerResponse struct {
	ClientId string `json:"client_id" binding:"required"`
}

func (server *Server) ClientsGetHandler(c *gin.Context) {
	var req struct {
		ClientId string `json:"client_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Bad request has been made, please check the parameters",
		})
		return
	}
	client, err := server.store.GetClientByID(c.Request.Context(), req.ClientId)
	if err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Client ID does not exist",
		})
		return
	}
	//TODO: Do not return client secret in production
	c.JSON(200, gin.H{
		"client_id":     client.ID,
		"client_name":   client.ClientName,
		"client_secret": client.ClientSecret,
		"redirect_uris": client.RedirectUris,
	})
	return
}
