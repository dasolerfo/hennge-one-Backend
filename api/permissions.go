package api

import (
	"database/sql"

	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/gin-gonic/gin"
)

type PermissionPostRequest struct {
	ClinetID string `json:"client_id" binding:"required"`
	UserID   int64  `json:"user_id" binding:"required"`
	Allowed  bool   `json:"allowed" binding:"required"`
}

func (server *Server) PermissionPostHandler(c *gin.Context) {

	var req PermissionPostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Bad request has been made, please check the parameters",
		})
		return
	}

	_, err := server.store.GetClientByID(c.Request.Context(), req.ClinetID)
	if err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_client",
			"error_description": "The client does not exist",
		})
	}

	_, err2 := server.store.GetUserByID(c.Request.Context(), req.UserID)

	if err2 != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_user",
			"error_description": "The user does not exist",
		})
		return
	}

	permission, err := server.store.GetPermissionByUserAndClient(c.Request.Context(), db.GetPermissionByUserAndClientParams{
		UserID:   req.UserID,
		ClientID: req.ClinetID,
	})

	if err != nil && err == sql.ErrNoRows {
		createdPermission, err := server.store.CreatePermission(c.Request.Context(), db.CreatePermissionParams{
			ClientID: req.ClinetID,
			UserID:   req.UserID,
			Allowed:  req.Allowed})

		if err != nil {
			c.JSON(500, gin.H{
				"error":             "server_error",
				"error_description": "Error creating the permission",
			})
			return
		}
		c.JSON(200, createdPermission)
		return

	} else {

		permission, err = server.store.UpdatePermission(c.Request.Context(), db.UpdatePermissionParams{
			UserID:   req.UserID,
			ClientID: req.ClinetID,
			Allowed:  req.Allowed,
		})

		if err != nil {
			c.JSON(500, gin.H{
				"error":             "server_error",
				"error_description": "Error updating the permission",
			})
			return
		}

		c.JSON(200, permission)
		return

	}

}
