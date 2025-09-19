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

const authType = "Bearer"

type AuthorizeGetHandlerRequest struct {
	Scope        string `form:"scope" binding:"required"`
	ResponseType string `form:"response_type" binding:"required"`
	RedirectUri  string `form:"redirect_uri" binding:"required"`
	State        string `form:"state" `
	ClintId      string `form:"client_id" binding:"required"`
	Prompt       string `form:"prompt"`
	Display      string `form:"display"`
	Nonce        string `form:"nonce"`
}

func (server *Server) AuthorizeGetHandler(c *gin.Context) {
	var req AuthorizeGetHandlerRequest
	if err := c.ShouldBindQuery(&req); err != nil {
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
	state := session.Get(StateCode)
	//TODO: Millorar aquesta chapuza
	var validAuth time.Time
	var valid bool
	validAuthStr, _ := session.Get(ValidUntil).(string)
	validAuth, err := time.Parse(time.RFC3339, validAuthStr)
	if err != nil {

	}
	//fmt.Println(err)
	if validAuthStr != "" {
		if time.Now().Before(validAuth) {
			valid = true
		} else {
			c.JSON(401, gin.H{
				"valid": validAuth.Format(time.RFC3339),
				"now":   time.Now().Format(time.RFC3339),
			})
		}

	}

	if req.Prompt == "login" && state != nil {
		if state.(string) != req.State {
			c.Redirect(302, "/login?scope="+req.Scope+"&response_type="+req.ResponseType+"&redirect_uri="+req.RedirectUri+"&state="+req.State+"&client_id="+req.ClintId+"&prompt="+req.Prompt+"&error=falloAqui")
			return
		}
	}

	if userID != nil && valid {

		if time.Now().Before(validAuth) {
			_, err := server.store.GetUserByID(c.Request.Context(), userID.(int64))

			if err != nil && err == sql.ErrNoRows {
				c.Redirect(302, "/login?scope="+req.Scope+"&response_type="+req.ResponseType+"&redirect_uri="+req.RedirectUri+"&state="+req.State+"&client_id="+req.ClintId+"&prompt="+req.Prompt+"&error=NopeFalloAqui")
				return
			} else if err != nil {
				redirectWithError := req.RedirectUri + "?error=server_error&error_description=Internal+server+error&state=" + req.State
				c.Redirect(http.StatusFound, redirectWithError)
				return
			}

			permission, err := server.store.GetPermissionByUserAndClient(c.Request.Context(), db.GetPermissionByUserAndClientParams{
				UserID:   userID.(int64),
				ClientID: req.ClintId,
			})

			if err != nil && err == sql.ErrNoRows {
				redirectWithError := req.RedirectUri + "?error=unauthorized_client&error_description=The+client+is+not+authorized+by+the+user&state=" + req.State
				c.Redirect(http.StatusFound, redirectWithError)
				return
			} else if err != nil {
				redirectWithError := req.RedirectUri + "?error=server_error&error_description=Internal+server+error&state=" + req.State
				c.Redirect(http.StatusFound, redirectWithError)
				return
			}

			if !permission.Allowed {
				redirectWithError := req.RedirectUri + "?error=unauthorized_client&error_description=The+client+is+not+authorized+by+the+user&state=" + req.State
				c.Redirect(http.StatusFound, redirectWithError)
				return
			}
			// Everything is correct, return to the redirect URI with the code
			ReturnToRedirectURI(*server, req, userID, c)

		}
		c.Redirect(302, "/login?scope="+req.Scope+"&response_type="+req.ResponseType+"&redirect_uri="+req.RedirectUri+"&state="+req.State+"&client_id="+req.ClintId+"&prompt="+req.Prompt+"&error=TornoAqui")
		return

	}

	if req.Prompt == "none" {
		redirectUri := req.RedirectUri + "?error=login_required&state=" + req.State
		c.Redirect(http.StatusFound, redirectUri)
		return
	}

	if req.Display == "none" {
		redirectUri := req.RedirectUri + "?error=interaction_required&state=" + req.State
		c.Redirect(http.StatusFound, redirectUri)
		return
	}

	c.Redirect(302, "/login?scope="+req.Scope+"&response_type="+req.ResponseType+"&redirect_uri="+req.RedirectUri+"&state="+req.State+"&client_id="+req.ClintId+"&prompt="+req.Prompt+"&error=PetoPerValidesa")

	return
}

func ReturnToRedirectURI(server Server, req AuthorizeGetHandlerRequest, userID interface{}, c *gin.Context) {

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
		CodeChallenge: sql.NullString{String: "RS256", Valid: true},
		Nonce:         sql.NullString{String: req.Nonce, Valid: true},
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

type InitiateLoginHandlerRequest struct {
	Issuer        string `form:"iss" bining:"required,http_url"`
	LoginHint     string `form:"login_hint"`
	TargetLinkUri string `form:"target_link_uri" binding:"http_url"`
}

func (server *Server) InitiateLoginHandler(c *gin.Context) {
	var req InitiateLoginHandlerRequest
	if err := c.ShouldBindQuery(&req); err != nil {
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
