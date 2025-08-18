package api

import "github.com/gin-gonic/gin"

type AuthorizeGetHandlerRequest struct {
	Scope        string `uri:"scope" binding:"required"`
	ResponseType string `uri:"response_type" binding:"required"`
	RedirectUri  string `uri:"redirect_uri" binding:"required"`
	State        string `uri:"state" `
	ClintId      string `uri:"client_id" binding:"required"`
	Prompt       string `uri:"prompt"`
}

func AuthorizeGetHandler(c *gin.Context) {
	var req AuthorizeGetHandlerRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request parameters"})
		return
	}

	if req.Scope != "openid" {
		c.JSON(400, gin.H{"error": "Invalid scope"})
		return
	}

}

func AuthorizePostHandler(c *gin.Context) {

}
