package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type DashboardLoginRequest struct {
	Code        string `json:"code" binding:"required"`
	RedirectUri string `json:"redirect_uri" binding:"required"`
	State       string `json:"state"`
	Nonce       string `json:"nonce"`
}

func (server *Server) DashboardLoginHandler(c *gin.Context) {
	var req DashboardLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	if req.RedirectUri != server.Config.DashboardRedirectURI {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "The redirect URI is not registered for the dashboard",
		})
		return
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {server.Config.DashboardClientID},
		"client_secret": {server.Config.DashboardClientSecret},
		"code":          {req.Code},
		"redirect_uri":  {req.RedirectUri},
	}

	httpReq, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, server.tokenEndpointURL(), strings.NewReader(form.Encode()))
	if err != nil {
		dashboardServerError(c, http.StatusInternalServerError, err)
		return
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := server.dashboardHTTPClient().Do(httpReq)
	if err != nil {
		dashboardServerError(c, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		dashboardServerError(c, http.StatusBadGateway, err)
		return
	}

	if resp.StatusCode == http.StatusOK && req.Nonce != "" {
		var tokens TokenPostHandlerResponse
		if err := json.Unmarshal(body, &tokens); err != nil {
			dashboardServerError(c, http.StatusBadGateway, err)
			return
		}
		idPayload, err := server.tokenMaker.VerifyIDToken(tokens.IdToken)
		if err != nil || idPayload.Nonce != req.Nonce {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "The ID token nonce does not match the login session",
			})
			return
		}
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	c.Data(resp.StatusCode, contentType, bytes.TrimSpace(body))
}

func (server *Server) tokenEndpointURL() string {
	ep := server.Config.TokenEndpoint
	if strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://") {
		return ep
	}
	return server.BuildHandlerURL(ep)
}

func (server *Server) dashboardHTTPClient() *http.Client {
	client := &http.Client{Timeout: 10 * time.Second}
	if server.Config.RunMode == "local" {
		// cert.pem is self-signed in local mode
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return client
}

func dashboardServerError(c *gin.Context, status int, err error) {
	log.Println("dashboard login:", err)
	c.JSON(status, gin.H{
		"error":             "server_error",
		"error_description": "Could not complete the token exchange",
	})
}
