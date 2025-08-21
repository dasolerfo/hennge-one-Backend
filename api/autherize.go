package api

import (
	"database/sql"
	"net/http"
	"time"

	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/dasolerfo/hennge-one-Backend.git/help"
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

func (server *Server) AuthorizeGetHandler(c *gin.Context) {
	var req AuthorizeGetHandlerRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(400, gin.H{"error_description": "Invalid request parameters"})
		return
	}

	if req.Scope != "openid" {
		redirectWithError := req.RedirectUri + "?error=invalid_scope&error_description=Authentification+type+not+supported+pringat&state=" + req.State
		c.Redirect(http.StatusFound, redirectWithError)
		return
	}
	if req.ResponseType != "code" {
		redirectWithError := req.RedirectUri + "?error=unsupported_response_type&error_description=Response+type+not+supported+pringat&state=" + req.State
		c.Redirect(http.StatusFound, redirectWithError)
		return
	}

	session := sessions.Default(c)
	userID := session.Get(SessionCodeKey)

	if userID != nil {
		accessCode, err := help.GenerateCode(32)
		if err != nil {
			c.HTML(500, "login.html", gin.H{"err": "Internal server error"})
			return
		}

		authCode, err := server.store.CreateAuthCode(c.Request.Context(), db.CreateAuthCodeParams{
			Code:          accessCode,
			ClientID:      req.ClintId,
			RedirectUri:   req.RedirectUri,
			Sub:           userID.(string),
			Scope:         sql.NullString{String: req.Scope, Valid: true},
			ExpiresAt:     time.Now().Add(server.Config.CodeExpirationTime),
			CodeChallenge: sql.NullString{String: "login", Valid: true},
		})

		if err != nil {
			c.HTML(500, "login.html", gin.H{"err": "Internal server error"})
			return
		}

		//if authCode  {
		c.Redirect(http.StatusFound, authCode.RedirectUri+"?code="+authCode.Code+"&state="+req.State)
		return
		//}

	}

	if req.Prompt == "none" {
		redirectUri := req.RedirectUri + "?error=login_required&state=" + req.State
		c.Redirect(http.StatusFound, redirectUri)
		return
	}

	c.Redirect(302, "/login?scope="+req.Scope+"&response_type="+req.ResponseType+"&redirect_uri="+req.RedirectUri+"&state="+req.State+"&client_id="+req.ClintId+"&prompt="+req.Prompt)
	return
}
