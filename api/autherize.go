package api

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

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
		c.JSON(400, gin.H{"error_description": "Invalid request parameters"})
		return
	}

	if req.Scope != "openid" {
		c.JSON(400, gin.H{"error_description": "Invalid scope"})
		return
	}

	session := sessions.Default(c)
	token := session.Get("token")

	if token != nil {

	}

	c.Redirect(302, "/login?scope="+req.Scope+"&response_type="+req.ResponseType+"&redirect_uri="+req.RedirectUri+"&state="+req.State+"&client_id="+req.ClintId+"&prompt="+req.Prompt)

}

func AuthorizePostHandler(c *gin.Context) {

}
