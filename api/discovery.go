package api

import "github.com/gin-gonic/gin"

/*
type DiscoveryResponse struct {
	Issuer            string   `json:"issuer"`
	Auth              string   `json:"authorization_endpoint"`
	Token             string   `json:"token_endpoint"`
	Keys              string   `json:"jwks_uri"`
	UserInfo          string   `json:"userinfo_endpoint"`
	DeviceEndpoint    string   `json:"device_authorization_endpoint"`
	Introspect        string   `json:"introspection_endpoint"`
	GrantTypes        []string `json:"grant_types_supported"`
	ResponseTypes     []string `json:"response_types_supported"`
	Subjects          []string `json:"subject_types_supported"`
	IDTokenAlgs       []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeAlgs []string `json:"code_challenge_methods_supported"`
	Scopes            []string `json:"scopes_supported"`
	AuthMethods       []string `json:"token_endpoint_auth_methods_supported"`
	Claims            []string `json:"claims_supported"`
}*/

type DiscoveryResponse struct {
	Issuer        string   `json:"issuer"`
	Auth          string   `json:"authorization_endpoint"`
	Token         string   `json:"token_endpoint"`
	Keys          string   `json:"jwks_uri"`
	ResponseTypes []string `json:"response_types_supported"`
	Subjects      []string `json:"subject_types_supported"`
	IDTokenAlgs   []string `json:"id_token_signing_alg_values_supported"`
}

func (server *Server) DiscoveryGetHandler(c *gin.Context) {

	response := &DiscoveryResponse{
		Issuer:        server.BuildIssuerURL(),
		Auth:          server.BuildHandlerURL(server.Config.AuthEndpoint),
		Token:         server.BuildHandlerURL(server.Config.TokenEndpoint),
		Keys:          server.BuildHandlerURL(server.Config.JwksEndpoint),
		ResponseTypes: []string{"code"},
		Subjects:      []string{"public"},
		IDTokenAlgs:   []string{"RS256"},
	}
	c.JSON(200, response)
	return
}
