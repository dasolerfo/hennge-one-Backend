package api

import "github.com/gin-gonic/gin"

func (server *Server) UserinfoGetHandler(c *gin.Context) {
	authorizationHeader := c.GetHeader("Authorization")
	if len(authorizationHeader) == 0 {
		c.JSON(401, gin.H{
			"error":             "invalid_request",
			"error_description": "No authorization header provided",
		})
		return
	}

	// Check if the authorization header is in the correct format
	const bearerPrefix = "Bearer "
	if len(authorizationHeader) < len(bearerPrefix) || authorizationHeader[:len(bearerPrefix)] != bearerPrefix {
		c.JSON(401, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid authorization header format",
		})
		return
	}

	// Extract the token from the authorization header
	accessToken := authorizationHeader[len(bearerPrefix):]

	payload, err := server.tokenMaker.VerifyAccessToken(accessToken)
	if err != nil {
		c.JSON(401, gin.H{
			"error":             "invalid_token",
			"error_description": "The access token is invalid or has expired",
		})
		return
	}

	user, err := server.store.GetUserByEmail(c.Request.Context(), payload.Email)
	if err != nil {
		c.JSON(500, gin.H{
			"error":             "server_error",
			"error_description": "Failed to retrieve user information",
		})
		return
	}

	response := gin.H{
		"sub":    payload.ID.String(),
		"name":   user.Name,
		"email":  user.Email,
		"gender": user.Gender,
	}
	if user.EmailVerified {
		response["email_verified"] = user.EmailVerified
	}

	c.JSON(200, response)
	return
}
