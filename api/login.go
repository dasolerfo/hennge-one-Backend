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

func (server *Server) DisplayLoginPage(c *gin.Context) {
	c.HTML(200, "login.html", gin.H{})
}

type LoginPostHandlerRequest struct {
	Email        string `json:"email" binding:"required,email"`
	Password     string `json:"password" binding:"required"`
	Scope        string `json:"scope" binding:"required"`
	ResponseType string `json:"response_type" binding:"required"`
	RedirectUri  string `json:"redirect_uri" binding:"required"`
	State        string `json:"state"`
	ClintId      string `json:"client_id" binding:"required"`
	Prompt       string `json:"prompt"`
}

func (server *Server) LoginPostHandler(c *gin.Context) {
	var req LoginPostHandlerRequest
	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		c.HTML(400, "login.html", gin.H{"error": "Invalid request parameters"})
	}
	server.store.

}
