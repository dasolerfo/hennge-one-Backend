package api

import "github.com/gin-gonic/gin"

type DiscoveryResponse struct {
	Issuer                   string   `json:"issuer"`
	Auth                     string   `json:"authorization_endpoint"`
	Token                    string   `json:"token_endpoint"`
	Keys                     string   `json:"jwks_uri"`
	UserInfo                 string   `json:"userinfo_endpoint"`
	ResponseTypes            []string `json:"response_types_supported"`
	Subjects                 []string `json:"subject_types_supported"`
	IDTokenAlgs              []string `json:"id_token_signing_alg_values_supported"`
	Scopes                   []string `json:"scopes_supported"`
	GrantTypes               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeAlgs        []string `json:"code_challenge_methods_supported,omitempty"`
	Claims                   []string `json:"claims_supported"`
}

func (server *Server) DiscoveryGetHandler(c *gin.Context) {

	response := &DiscoveryResponse{
		Issuer:                   server.BuildIssuerURL(),
		Auth:                     server.BuildHandlerURL(server.Config.AuthEndpoint),
		Token:                    server.BuildHandlerURL(server.Config.TokenEndpoint),
		Keys:                     server.BuildHandlerURL(server.Config.JwksEndpoint),
		UserInfo:                 server.BuildHandlerURL(server.Config.UserinfoEndpoint),
		ResponseTypes:            []string{"code"},
		Subjects:                 []string{"public"},
		IDTokenAlgs:              []string{"RS256"},
		Scopes:                   []string{"openid"},
		GrantTypes:               []string{"authorization_code"},
		TokenEndpointAuthMethods: []string{"client_secret_post"},
		// PKCE isn't implemented (no code_challenge handling in /authorize or /token),
		// so this is left unset rather than advertising support the server doesn't have.
		Claims: []string{"sub", "name", "email", "email_verified", "gender"},
	}
	c.JSON(200, response)

}

// JwksGetHandler serves the JSON Web Key Set (JWKS) at the /.well-known/jwks.json endpoint
func (server *Server) JwksGetHandler(c *gin.Context) {
	c.JSON(200, server.tokenMaker.Jwks())

}
