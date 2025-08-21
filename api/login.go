package api

import (
	"strconv"

	"github.com/dasolerfo/hennge-one-Backend.git/help"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	SessionCodeKey = "loggedCode"
)

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
		c.HTML(401, "login.html", gin.H{"error": "Invalid request parameters"})
	}
	user, err := server.store.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		c.HTML(401, "login.html", gin.H{"error": "User not found"})
		return
	}

	if err := help.CheckPassword(req.Password, user.HashedPassword); err != nil {
		c.HTML(401, "login.html", gin.H{"error": "Invalid password"})
		return
	}

	id := strconv.FormatInt(user.ID, 10)

	session := sessions.Default(c)
	session.Set(SessionCodeKey, id)
	session.Save()

	c.Redirect(302, "/authorize?scope="+req.Scope+"&response_type="+req.ResponseType+"&redirect_uri="+req.RedirectUri+"&state="+req.State+"&client_id="+req.ClintId+"&prompt="+req.Prompt)
	return
}
