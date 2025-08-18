package api

import "github.com/gin-gonic/gin"

type DisplayLoginPageRequest struct {
	Scope        string `uri:"scope" binding:"required"`
	ResponseType string `uri:"response_type" binding:"required"`
	RedirectUri  string `uri:"redirect_uri" binding:"required"`
	State        string `uri:"state"`
	ClintId      string `uri:"client_id" binding:"required"`
	Prompt       string `uri:"prompt"`
}

func DisplayLoginPage(c *gin.Context) {
	c.HTML(200, "login.html", gin.H{})
}

func LoginPostHandler(c *gin.Context) {

}
