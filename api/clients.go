package api

import (
	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/gin-gonic/gin"
)

type ClientRegisterRequest struct {
	ClientSource string   `json:"client_source" binding:"required"`
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
	_, err := server.store.GetClientBysource(c.Request.Context(), req.ClientSource)
	if err == nil {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Client ID already exists",
		})
		return
	}

	client, err := server.store.CreateClient(c.Request.Context(), db.CreateClientParams{
		ClientSource: req.ClientSource,
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
}

type ClientsGetHandlerResponse struct {
	ClientId int64 `json:"client_id" binding:"required"`
}

func (server *Server) ClientsGetHandler(c *gin.Context) {
	var req struct {
		ClientId int64 `json:"client_id" binding:"required"`
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
		"client_source": client.ClientSource,
		"client_name":   client.ClientName,
		"client_secret": client.ClientSecret,
		"redirect_uris": client.RedirectUris,
	})

}

func (server *Server) GetAllClientsHandler(c *gin.Context) {
	clients, err := server.store.ListClients(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{
			"error":             "server_error",
			"error_description": "Failed to retrieve clients",
		})
		return
	}

	c.JSON(200, gin.H{
		"clients": clients,
	})
}

func (server *Server) GetClientHandler(c *gin.Context) {
	var uri idURIRequest
	if err := c.ShouldBindUri(&uri); err != nil {
		badRequest(c)
		return
	}

	client, err := server.store.GetClientByID(c.Request.Context(), uri.ID)
	if err != nil {
		dbError(c, err, "Client does not exist", "Failed to retrieve the client")
		return
	}

	c.JSON(200, client)
}

type UpdateClientRequest struct {
	ClientSource *string  `json:"client_source" binding:"omitempty,min=1"`
	ClientName   *string  `json:"client_name" binding:"omitempty,min=1"`
	ClientSecret *string  `json:"client_secret" binding:"omitempty,min=1"`
	RedirectUris []string `json:"redirect_uris" binding:"omitempty,min=1"`
}

func (server *Server) UpdateClientHandler(c *gin.Context) {
	var uri idURIRequest
	if err := c.ShouldBindUri(&uri); err != nil {
		badRequest(c)
		return
	}
	var req UpdateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c)
		return
	}

	client, err := server.store.UpdateClient(c.Request.Context(), db.UpdateClientParams{
		ID:           uri.ID,
		ClientSource: nullString(req.ClientSource),
		ClientName:   nullString(req.ClientName),
		ClientSecret: nullString(req.ClientSecret),
		RedirectUris: req.RedirectUris, // nil keeps the current value
	})
	if err != nil {
		dbError(c, err, "Client does not exist", "Failed to update the client")
		return
	}

	c.JSON(200, client)
}

func (server *Server) DeleteClientHandler(c *gin.Context) {
	var uri idURIRequest
	if err := c.ShouldBindUri(&uri); err != nil {
		badRequest(c)
		return
	}

	if _, err := server.store.GetClientByID(c.Request.Context(), uri.ID); err != nil {
		dbError(c, err, "Client does not exist", "Failed to delete the client")
		return
	}
	if err := server.store.DeleteClient(c.Request.Context(), uri.ID); err != nil {
		dbError(c, err, "Client does not exist", "Failed to delete the client")
		return
	}

	c.JSON(200, gin.H{"message": "Client deleted successfully"})
}
