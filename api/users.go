package api

import (
	"database/sql"
	"errors"
	"time"

	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/dasolerfo/hennge-one-Backend.git/help"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// idURIRequest binds the ":id" path parameter shared by the CRUD endpoints.
type idURIRequest struct {
	ID int64 `uri:"id" binding:"required,min=1"`
}

type userResponse struct {
	ID            int64     `json:"id"`
	Sub           uuid.UUID `json:"sub"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Gender        string    `json:"gender,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

func newUserResponse(u db.User) userResponse {
	return userResponse{
		ID:            u.ID,
		Sub:           u.Sub,
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Gender:        u.Gender.String,
		CreatedAt:     u.CreatedAt,
	}
}

func nullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func nullBool(b *bool) sql.NullBool {
	if b == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: *b, Valid: true}
}

func badRequest(c *gin.Context) {
	c.JSON(400, gin.H{
		"error":             "invalid_request",
		"error_description": "Bad request has been made, please check the parameters",
	})
}

// dbError maps a store error to the corresponding HTTP response.
func dbError(c *gin.Context, err error, notFoundMsg, serverMsg string) {
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(404, gin.H{"error": "not_found", "error_description": notFoundMsg})
		return
	}
	c.JSON(500, gin.H{"error": "server_error", "error_description": serverMsg})
}

func (server *Server) GetUserHandler(c *gin.Context) {
	var uri idURIRequest
	if err := c.ShouldBindUri(&uri); err != nil {
		badRequest(c)
		return
	}

	user, err := server.store.GetUserByID(c.Request.Context(), uri.ID)
	if err != nil {
		dbError(c, err, "User does not exist", "Failed to retrieve the user")
		return
	}

	c.JSON(200, newUserResponse(user))
}

type UpdateUserRequest struct {
	Name          *string `json:"name" binding:"omitempty,min=1"`
	Email         *string `json:"email" binding:"omitempty,email"`
	Password      *string `json:"password" binding:"omitempty,min=6"`
	Gender        *string `json:"gender"`
	EmailVerified *bool   `json:"email_verified"`
}

func (server *Server) UpdateUserHandler(c *gin.Context) {
	var uri idURIRequest
	if err := c.ShouldBindUri(&uri); err != nil {
		badRequest(c)
		return
	}
	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c)
		return
	}

	arg := db.UpdateUserParams{
		ID:            uri.ID,
		Name:          nullString(req.Name),
		Email:         nullString(req.Email),
		Gender:        nullString(req.Gender),
		EmailVerified: nullBool(req.EmailVerified),
	}
	if req.Password != nil {
		hashed, err := help.HashPassword(*req.Password)
		if err != nil {
			c.JSON(500, gin.H{"error": "server_error", "error_description": "Failed to hash the password"})
			return
		}
		arg.HashedPassword = sql.NullString{String: hashed, Valid: true}
	}

	user, err := server.store.UpdateUser(c.Request.Context(), arg)
	if err != nil {
		dbError(c, err, "User does not exist", "Failed to update the user")
		return
	}

	c.JSON(200, newUserResponse(user))
}

func (server *Server) DeleteUserHandler(c *gin.Context) {
	var uri idURIRequest
	if err := c.ShouldBindUri(&uri); err != nil {
		badRequest(c)
		return
	}

	if _, err := server.store.GetUserByID(c.Request.Context(), uri.ID); err != nil {
		dbError(c, err, "User does not exist", "Failed to delete the user")
		return
	}
	if err := server.store.DeleteUser(c.Request.Context(), uri.ID); err != nil {
		dbError(c, err, "User does not exist", "Failed to delete the user")
		return
	}

	c.JSON(200, gin.H{"message": "User deleted successfully"})
}
