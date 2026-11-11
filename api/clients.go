package api

import (
	"database/sql"

	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/gin-gonic/gin"
)

type ClientRegisterRequest struct {
	ClientSource string   `json:"client_source" binding:"required"`
	ClientName   string   `json:"client_name" binding:"required"`
	ClientSecret string   `json:"client_secret"`
	RedirectUris []string `json:"redirect_uris" binding:"required,min=1"`
	// Optional OAuth settings; see withDefaults for the defaults.
	ClientType              string   `json:"client_type" binding:"omitempty,oneof=public confidential"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	RequirePkce             *bool    `json:"require_pkce"`
}

// withDefaults fills in the OAuth settings the request left out:
// confidential client, secret sent in the form body, authorization_code,
// PKCE required (always for public clients).
func (req ClientRegisterRequest) withDefaults() clientConfig {
	cfg := clientConfig{
		ClientType:              req.ClientType,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		ClientSecret:            req.ClientSecret,
		GrantTypes:              req.GrantTypes,
		RequirePkce:             true,
	}
	if cfg.ClientType == "" {
		cfg.ClientType = ClientTypeConfidential
	}
	if cfg.TokenEndpointAuthMethod == "" {
		if cfg.ClientType == ClientTypePublic {
			cfg.TokenEndpointAuthMethod = AuthMethodNone
		} else {
			cfg.TokenEndpointAuthMethod = AuthMethodClientSecretPost
		}
	}
	if len(cfg.GrantTypes) == 0 {
		cfg.GrantTypes = []string{GrantTypeAuthorizationCode}
	}
	if req.RequirePkce != nil {
		cfg.RequirePkce = *req.RequirePkce
	}
	return cfg
}

func invalidClientMetadata(c *gin.Context, err error) {
	c.JSON(400, gin.H{
		"error":             "invalid_client_metadata",
		"error_description": err.Error(),
	})
}

// clientResponse is a client without its secret.
func clientResponse(client db.Client) gin.H {
	return gin.H{
		"client_id":                  client.ID,
		"client_source":              client.ClientSource,
		"client_name":                client.ClientName,
		"redirect_uris":              client.RedirectUris,
		"client_type":                client.ClientType,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"grant_types":                client.GrantTypes,
		"require_pkce":               client.RequirePkce,
		"created_at":                 client.CreatedAt,
	}
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
	cfg := req.withDefaults()
	if err := cfg.validate(); err != nil {
		invalidClientMetadata(c, err)
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
		ClientSource:            req.ClientSource,
		ClientName:              req.ClientName,
		ClientSecret:            cfg.ClientSecret,
		RedirectUris:            req.RedirectUris,
		ClientType:              cfg.ClientType,
		TokenEndpointAuthMethod: cfg.TokenEndpointAuthMethod,
		GrantTypes:              cfg.GrantTypes,
		RequirePkce:             cfg.RequirePkce,
	})
	if err != nil {
		c.JSON(500, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
		return
	}

	c.JSON(200, gin.H{
		"message":  "Client registered successfully!",
		"response": clientResponse(client),
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

	c.JSON(200, clientResponse(client))
}

type UpdateClientRequest struct {
	ClientSource            *string  `json:"client_source" binding:"omitempty,min=1"`
	ClientName              *string  `json:"client_name" binding:"omitempty,min=1"`
	ClientSecret            *string  `json:"client_secret" binding:"omitempty,min=1"`
	RedirectUris            []string `json:"redirect_uris" binding:"omitempty,min=1"`
	ClientType              *string  `json:"client_type" binding:"omitempty,oneof=public confidential"`
	TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types" binding:"omitempty,min=1"`
	RequirePkce             *bool    `json:"require_pkce"`
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

	current, err := server.store.GetClientByID(c.Request.Context(), uri.ID)
	if err != nil {
		dbError(c, err, "Client does not exist", "Failed to update the client")
		return
	}

	// Apply the changes on top of the current settings and validate the result,
	// so e.g. switching to "public" without also changing the auth method fails cleanly.
	cfg := clientConfig{
		ClientType:              current.ClientType,
		TokenEndpointAuthMethod: current.TokenEndpointAuthMethod,
		ClientSecret:            current.ClientSecret,
		GrantTypes:              current.GrantTypes,
		RequirePkce:             current.RequirePkce,
	}
	if req.ClientType != nil {
		cfg.ClientType = *req.ClientType
		if cfg.ClientType == ClientTypePublic {
			cfg.ClientSecret = "" // public clients never keep a secret
		}
	}
	if req.TokenEndpointAuthMethod != nil {
		cfg.TokenEndpointAuthMethod = *req.TokenEndpointAuthMethod
	}
	if req.ClientSecret != nil {
		cfg.ClientSecret = *req.ClientSecret
	}
	if req.GrantTypes != nil {
		cfg.GrantTypes = req.GrantTypes
	}
	if req.RequirePkce != nil {
		cfg.RequirePkce = *req.RequirePkce
	}
	if err := cfg.validate(); err != nil {
		invalidClientMetadata(c, err)
		return
	}

	client, err := server.store.UpdateClient(c.Request.Context(), db.UpdateClientParams{
		ID:                      uri.ID,
		ClientSource:            nullString(req.ClientSource),
		ClientName:              nullString(req.ClientName),
		RedirectUris:            req.RedirectUris, // nil keeps the current value
		ClientSecret:            sql.NullString{String: cfg.ClientSecret, Valid: true},
		ClientType:              sql.NullString{String: cfg.ClientType, Valid: true},
		TokenEndpointAuthMethod: sql.NullString{String: cfg.TokenEndpointAuthMethod, Valid: true},
		GrantTypes:              cfg.GrantTypes,
		RequirePkce:             sql.NullBool{Bool: cfg.RequirePkce, Valid: true},
	})
	if err != nil {
		dbError(c, err, "Client does not exist", "Failed to update the client")
		return
	}

	c.JSON(200, clientResponse(client))
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
