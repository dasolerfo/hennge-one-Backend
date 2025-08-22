package api

import (
	"github.com/gin-gonic/gin"
)

func TokenGetHandler(c *gin.Context) {

}

type TokenPostHandlerRequest struct {
	GrantType   string `form:"grant_type" binding:"required"`
	ClientID    string `form:"client_id" binding:"required"`
	RedirectUri string `form:"redirect_uri" binding:"required"`
	Code        string `form:"code" binding:"required"`
}
type TokenPostHandlerResponse struct {
	AccessToken  string `json:"access_token"`
	TockenType   string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IdToken      string `json:"id_token"`
}

func (server *Server) TokenPostHandler(c *gin.Context) {
	var req TokenPostHandlerRequest
	if err := c.ShouldBind(&req); err != nil {
		// TODO: Afegir la validació dels errors correctament
	}
	authCode, err := server.store.GetAuthCode(c.Request.Context(), req.Code)
	if err != nil {
		// Validar correctament l'error
	}
	if authCode.ClientID != req.ClientID {
		// Validar correctament l'error
	}
	if req.RedirectUri != "" && authCode.RedirectUri != req.RedirectUri {
		// Validar correctamnet l'error
	}
	if authCode.Scope.String != "openid" {
		//Validar correctament l'error
	}

	idtoken, payload, err := server.tokenMaker.CreateIDToken(req.ClientID, authCode.Sub, []string{req.ClientID}, server.Config.TokenDuration)

	response := &TokenPostHandlerResponse{
		IdToken:    idtoken,
		ExpiresIn:  payload.ExpiredAt,
		TockenType: "Bearer",
	}

}
