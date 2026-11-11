package api

import (
	"net/url"
	"slices"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TokenGetHandler(c *gin.Context) {

}

type TokenPostHandlerRequest struct {
	GrantType   string `form:"grant_type" binding:"required"`
	RedirectUri string `form:"redirect_uri" binding:"required"`
	Code        string `form:"code" binding:"required"`
	// Client authentication: either these form fields or an HTTP Basic header.
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	// PKCE (RFC 7636)
	CodeVerifier string `form:"code_verifier"`
}
type TokenPostHandlerResponse struct {
	AccessToken  string `json:"access_token"`
	TockenType   string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IdToken      string `json:"id_token"`
}

func invalidClient(c *gin.Context, usedBasic bool, description string) {
	status := 400
	if usedBasic {
		// RFC 6749 §5.2: answer 401 when the client tried the Authorization header.
		c.Header("WWW-Authenticate", `Basic realm="token"`)
		status = 401
	}
	c.JSON(status, gin.H{
		"error":             "invalid_client",
		"error_description": description,
	})
}

func (server *Server) TokenPostHandler(c *gin.Context) {
	var req TokenPostHandlerRequest

	if err := c.ShouldBind(&req); err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	if !slices.Contains(supportedGrantTypes, req.GrantType) {
		c.JSON(400, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Only the authorization_code grant type is supported",
		})
		return
	}

	// 1. Authenticate the client with the method it registered.
	creds, err := extractClientCredentials(c, req.ClientID, req.ClientSecret)
	if err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	usedBasic := creds.Method == AuthMethodClientSecretBasic
	clientID, err := strconv.ParseInt(creds.ClientID, 10, 64)
	if err != nil {
		invalidClient(c, usedBasic, "The client ID is invalid")
		return
	}
	client, err := server.store.GetClientByID(c.Request.Context(), clientID)
	if err != nil {
		invalidClient(c, usedBasic, "The client ID is invalid")
		return
	}
	if creds.Method != client.TokenEndpointAuthMethod {
		invalidClient(c, usedBasic, "The client must authenticate with "+client.TokenEndpointAuthMethod)
		return
	}
	if creds.Method != AuthMethodNone && !secretsEqual(creds.Secret, client.ClientSecret) {
		invalidClient(c, usedBasic, "The client secret is invalid")
		return
	}
	if !slices.Contains(client.GrantTypes, req.GrantType) {
		c.JSON(400, gin.H{
			"error":             "unauthorized_client",
			"error_description": "The client is not allowed to use this grant type",
		})
		return
	}

	// 2. Validate the authorization code.
	authCode, err := server.store.GetAuthCode(c.Request.Context(), req.Code)
	if err != nil {
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "The authorization code is invalid or has expired",
		})
		return
	}
	if authCode.Used {
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "The authorization code has already been used",
		})
		return
	}
	if authCode.ClientID != client.ID {
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "The client ID does not match the one used in the authorization request",
		})
		return
	}

	// 3. PKCE.
	hasChallenge := authCode.CodeChallenge.Valid && authCode.CodeChallenge.String != ""
	switch {
	case hasChallenge && req.CodeVerifier == "":
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "code_verifier is required",
		})
		return
	case hasChallenge && !verifyCodeVerifier(req.CodeVerifier, authCode.CodeChallenge.String):
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "The code_verifier does not match the code_challenge",
		})
		return
	case !hasChallenge && req.CodeVerifier != "":
		// Prevents PKCE downgrade attacks (RFC 9700 §2.1.1).
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "code_verifier sent but the authorization request had no code_challenge",
		})
		return
	case !hasChallenge && client.RequirePkce:
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "This client requires PKCE",
		})
		return
	}

	parsedRedirectUri, err := url.QueryUnescape(req.RedirectUri)

	if err != nil || parsedRedirectUri == "" {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "The redirect URI is not valid",
		})
		return
	}

	if req.RedirectUri != "" && authCode.RedirectUri != parsedRedirectUri {
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "The redirect URI does not match with the one used in the authorization request",
		})
		return
	}
	if authCode.Scope.String != "openid" {
		c.JSON(400, gin.H{
			"error":             "invalid_scope",
			"error_description": "The scope is not valid",
		})
		return
	}
	// Mark the code as used
	err = server.store.SetCodeUsed(c.Request.Context(), req.Code)
	if err != nil {
		c.JSON(500, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
		return
	}
	stringClientID := strconv.FormatInt(client.ID, 10)

	idtoken, payload, err := server.tokenMaker.CreateIDToken(server.Config.Issuer, authCode.Sub, []string{stringClientID}, authCode.CreatedAt.Unix(), server.Config.TokenDuration, authCode.Nonce.String)
	userSub, err := uuid.Parse(authCode.Sub)
	if err != nil {
		c.JSON(500, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
		return
	}
	user, err := server.store.GetUserBySub(c.Request.Context(), userSub)

	if err != nil {
		c.JSON(500, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
		return
	}
	accessToken, _, err := server.tokenMaker.CreateToken(server.Config.Issuer, authCode.Sub, user.Email, server.Config.TokenDuration)

	response := &TokenPostHandlerResponse{
		IdToken:     idtoken,
		ExpiresIn:   payload.ExpiredAt,
		TockenType:  "Bearer",
		AccessToken: accessToken,
	}

	c.JSON(200, response)

}
