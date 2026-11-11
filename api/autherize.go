package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/dasolerfo/hennge-one-Backend.git/help"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const authType = "Bearer"

type AuthorizeGetHandlerRequest struct {
	Scope               string `form:"scope" binding:"required"`
	ResponseType        string `form:"response_type" binding:"required"`
	RedirectUri         string `form:"redirect_uri" binding:"required"`
	State               string `form:"state" `
	ClintId             string `form:"client_id" binding:"required"`
	Prompt              string `form:"prompt"`
	Display             string `form:"display"`
	Nonce               string `form:"nonce"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
}

// query rebuilds the authorization request parameters so they survive the
// round trip through /login.
func (req AuthorizeGetHandlerRequest) query() url.Values {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("scope", req.Scope)
	set("response_type", req.ResponseType)
	set("redirect_uri", req.RedirectUri)
	set("state", req.State)
	set("client_id", req.ClintId)
	set("prompt", req.Prompt)
	set("display", req.Display)
	set("nonce", req.Nonce)
	set("code_challenge", req.CodeChallenge)
	set("code_challenge_method", req.CodeChallengeMethod)
	return q
}

func redirectToLogin(c *gin.Context, req AuthorizeGetHandlerRequest, debugTag string) {
	q := req.query()
	q.Set("error", debugTag)
	c.Redirect(http.StatusFound, "/login?"+q.Encode())
}

// redirectWithError sends an OAuth error back to the (already validated) redirect URI.
func redirectWithError(c *gin.Context, req AuthorizeGetHandlerRequest, code, description string) {
	q := url.Values{}
	q.Set("error", code)
	q.Set("error_description", description)
	if req.State != "" {
		q.Set("state", req.State)
	}
	c.Redirect(http.StatusFound, req.RedirectUri+"?"+q.Encode())
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

	// Validate the client and redirect URI first. Until the redirect URI is known
	// to be registered we must not redirect to it (RFC 6749 §4.1.2.1).
	clientID, err := strconv.ParseInt(req.ClintId, 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_client", "error_description": "The client ID is invalid"})
		return
	}
	client, err := server.store.GetClientByID(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_client", "error_description": "The client does not exist"})
		return
	}
	if client.RedirectUris == nil || !help.StringInSlice(req.RedirectUri, client.RedirectUris) {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "The redirect URI is not valid"})
		return
	}

	/* if req.Scope != "openid" {
		redirectWithError := req.RedirectUri + "?error=invalid_scope&error_description=Authentification+type+not+supported+pringat&state=" + req.State
		c.Redirect(http.StatusFound, redirectWithError)
		return
	}*/
	if req.ResponseType != "code" {
		redirectWithError(c, req, "unsupported_response_type", "Only the code response type is supported")
		return
	}
	if !slices.Contains(client.GrantTypes, GrantTypeAuthorizationCode) {
		redirectWithError(c, req, "unauthorized_client", "The client is not allowed to use the authorization code flow")
		return
	}

	// PKCE
	if req.CodeChallenge != "" {
		if err := validateCodeChallenge(req.CodeChallenge, req.CodeChallengeMethod); err != nil {
			redirectWithError(c, req, "invalid_request", err.Error())
			return
		}
	} else if req.CodeChallengeMethod != "" {
		redirectWithError(c, req, "invalid_request", "code_challenge_method sent without code_challenge")
		return
	} else if client.RequirePkce {
		redirectWithError(c, req, "invalid_request", "This client requires PKCE (code_challenge with S256)")
		return
	}

	session := sessions.Default(c)
	userID := session.Get(SessionCodeKey)
	state := session.Get(StateCode)

	if req.Prompt == "login" {
		sessionState, _ := state.(string)
		if sessionState != req.State {
			redirectToLogin(c, req, "falloAqui")
			return
		}
	}

	if userID != nil {
		userSub, err := uuid.Parse(userID.(string))
		if err != nil {
			redirectWithError(c, req, "invalid_request", "The user ID is invalid")
			return
		}
		_, err = server.store.GetUserBySub(c.Request.Context(), userSub)

		if err != nil && err == sql.ErrNoRows {
			redirectToLogin(c, req, "NopeFalloAqui")
			return
		} else if err != nil {
			redirectWithError(c, req, "server_error", "Internal server error")
			return
		}

		// Everything is correct, return to the redirect URI with the code
		ReturnToRedirectURI(*server, req, userID, c)
		return
	}

	if req.Prompt == "none" {
		redirectWithError(c, req, "login_required", "The user is not logged in")
		return
	}

	if req.Display == "none" {
		redirectWithError(c, req, "interaction_required", "User interaction is required")
		return
	}

	redirectToLogin(c, req, "PetoPerValidesa")
}

func ReturnToRedirectURI(server Server, req AuthorizeGetHandlerRequest, userID interface{}, c *gin.Context) {

	accessCode, err := help.GenerateCode(32)
	if err != nil {
		c.HTML(500, "login.html", gin.H{"err": "Internal server error"})
		return
	}
	clientID, err := strconv.ParseInt(req.ClintId, 10, 64)

	if err != nil {
		redirectWithError(c, req, "invalid_client", "The client ID is invalid")
		return
	}

	authCode, err := server.store.CreateAuthCode(c.Request.Context(), db.CreateAuthCodeParams{
		Code:                accessCode,
		ClientID:            clientID,
		RedirectUri:         req.RedirectUri,
		Sub:                 userID.(string),
		Scope:               sql.NullString{String: req.Scope, Valid: true},
		ExpiresAt:           time.Now().Add(server.Config.CodeExpirationTime),
		CodeChallenge:       sql.NullString{String: req.CodeChallenge, Valid: req.CodeChallenge != ""},
		CodeChallengeMethod: sql.NullString{String: req.CodeChallengeMethod, Valid: req.CodeChallenge != ""},
		Nonce:               sql.NullString{String: req.Nonce, Valid: req.Nonce != ""},
	})

	if err != nil {
		c.HTML(500, "login.html", gin.H{"err": "Internal server error"})
		return
	}

	q := url.Values{}
	q.Set("code", authCode.Code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	c.Redirect(http.StatusFound, authCode.RedirectUri+"?"+q.Encode())

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
