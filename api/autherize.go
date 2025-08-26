package api

import (
	"database/sql"
	"encoding/json"
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
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request parameters",
		})
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

type InitiateLoginHandlerRequest struct {
	Issuer        string `uri:"iss" bining:"required,http_url"`
	LoginHint     string `uri:"login_hint"`
	TargetLinkUri string `uri:"target_link_uri" binding:"http_url"`
}

func (server *Server) InitiateLoginHandler(c *gin.Context) {
	var req InitiateLoginHandlerRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request parameters",
		})
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	reqApi, err := http.NewRequest("GET", req.Issuer+"/well-known/openid-configuration", nil)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed_to_create_request"})
		return
	}

	// Optionally, set headers
	reqApi.Header.Set("Accept", "application/json")

	resp, err := client.Do(reqApi)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed_to_call_external_api"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(resp.StatusCode, gin.H{"error": "external_api_error"})
		return
	}

	type OIDCConfiguration struct {
		Issuer                           string   `json:"issuer"`
		AuthorizationEndpoint            string   `json:"authorization_endpoint"`
		TokenEndpoint                    string   `json:"token_endpoint"`
		UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
		JwksURI                          string   `json:"jwks_uri"`
		ResponseTypesSupported           []string `json:"response_types_supported"`
		SubjectTypesSupported            []string `json:"subject_types_supported"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
		ScopesSupported                  []string `json:"scopes_supported"`
	}

	var result OIDCConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		c.JSON(500, gin.H{"error": "failed_to_parse_response"})
		return
	}

	c.Redirect(302, "/authorize?issuer="+result.Issuer+"&scope=openid&response_type=code&redirect_uri="+req.TargetLinkUri+"&state=initiate_login&client_id=hennge-one-client&prompt=login")

	return
	/*if req.Issuer != server.BuildIssuerURL() {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid issuer",
		})
		return
	}

	redirectUri := "/login?scope=openid&response_type=code&redirect_uri=" + req.TargetLinkUri + "&state=initiate_login&client_id=hennge-one-client&prompt=login"
	c.Redirect(302, redirectUri)*/
}
