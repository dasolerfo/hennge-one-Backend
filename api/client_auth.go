package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"slices"

	"github.com/gin-gonic/gin"
)

// Client types (RFC 6749 §2.1).
const (
	ClientTypePublic       = "public"
	ClientTypeConfidential = "confidential"
)

// Token endpoint authentication methods (RFC 7591 §2).
const (
	AuthMethodNone              = "none"
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
)

// Grant types.
const (
	GrantTypeAuthorizationCode = "authorization_code"
)

// PKCE (RFC 7636). Only S256 is accepted; "plain" is deliberately rejected.
const PKCEMethodS256 = "S256"

var (
	// Grant types this server can actually issue tokens for.
	supportedGrantTypes  = []string{GrantTypeAuthorizationCode}
	supportedAuthMethods = []string{AuthMethodNone, AuthMethodClientSecretBasic, AuthMethodClientSecretPost}

	// code_verifier: 43-128 chars from the unreserved set (RFC 7636 §4.1).
	codeVerifierRe = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)
	// code_challenge for S256: base64url(SHA-256) without padding is always 43 chars.
	codeChallengeS256Re = regexp.MustCompile(`^[A-Za-z0-9\-_]{43}$`)
)

// clientConfig is the security-relevant part of a client registration.
type clientConfig struct {
	ClientType              string
	TokenEndpointAuthMethod string
	ClientSecret            string
	GrantTypes              []string
	RequirePkce             bool
}

// validate enforces the rules that tie client type, auth method, secret and PKCE together.
// The database has equivalent CHECK constraints; this gives readable 400 errors instead.
func (cfg clientConfig) validate() error {
	if !slices.Contains(supportedAuthMethods, cfg.TokenEndpointAuthMethod) {
		return errors.New("unsupported token_endpoint_auth_method")
	}
	if len(cfg.GrantTypes) == 0 {
		return errors.New("grant_types cannot be empty")
	}
	for _, g := range cfg.GrantTypes {
		if !slices.Contains(supportedGrantTypes, g) {
			return errors.New("unsupported grant type: " + g)
		}
	}

	switch cfg.ClientType {
	case ClientTypePublic:
		if cfg.TokenEndpointAuthMethod != AuthMethodNone {
			return errors.New("public clients must use token_endpoint_auth_method \"none\"")
		}
		if cfg.ClientSecret != "" {
			return errors.New("public clients cannot have a client_secret")
		}
		if !cfg.RequirePkce {
			return errors.New("public clients must require PKCE")
		}
	case ClientTypeConfidential:
		if cfg.TokenEndpointAuthMethod == AuthMethodNone {
			return errors.New("confidential clients must authenticate with a client secret")
		}
		if cfg.ClientSecret == "" {
			return errors.New("confidential clients require a client_secret")
		}
	default:
		return errors.New("client_type must be \"public\" or \"confidential\"")
	}
	return nil
}

// clientCredentials are the credentials a client presented at the token endpoint.
type clientCredentials struct {
	ClientID string
	Secret   string
	Method   string // the auth method the client actually used
}

// extractClientCredentials reads client authentication from the request, accepting
// HTTP Basic (client_secret_basic), form fields (client_secret_post) or just a
// client_id (none). Using more than one mechanism at once is rejected (RFC 6749 §2.3).
func extractClientCredentials(c *gin.Context, formClientID, formSecret string) (clientCredentials, error) {
	if user, pass, ok := c.Request.BasicAuth(); ok {
		if formSecret != "" {
			return clientCredentials{}, errors.New("multiple client authentication methods used")
		}
		// Basic credentials are form-urlencoded before base64 (RFC 6749 §2.3.1).
		id, err1 := url.QueryUnescape(user)
		secret, err2 := url.QueryUnescape(pass)
		if err1 != nil || err2 != nil {
			return clientCredentials{}, errors.New("malformed Basic credentials")
		}
		if formClientID != "" && formClientID != id {
			return clientCredentials{}, errors.New("client_id does not match the Authorization header")
		}
		return clientCredentials{ClientID: id, Secret: secret, Method: AuthMethodClientSecretBasic}, nil
	}
	if formClientID == "" {
		return clientCredentials{}, errors.New("client_id is required")
	}
	if formSecret != "" {
		return clientCredentials{ClientID: formClientID, Secret: formSecret, Method: AuthMethodClientSecretPost}, nil
	}
	return clientCredentials{ClientID: formClientID, Method: AuthMethodNone}, nil
}

func secretsEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// validateCodeChallenge checks the PKCE parameters sent to /authorize.
func validateCodeChallenge(challenge, method string) error {
	if method != PKCEMethodS256 {
		// An absent method means "plain" (RFC 7636 §4.3), which we don't accept.
		return errors.New("code_challenge_method must be S256")
	}
	if !codeChallengeS256Re.MatchString(challenge) {
		return errors.New("code_challenge is malformed")
	}
	return nil
}

// verifyCodeVerifier checks a code_verifier against the stored S256 challenge.
func verifyCodeVerifier(verifier, challenge string) bool {
	if !codeVerifierRe.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
