package token

import "time"

type Maker interface {
	// CreateToken creates a new token for the given email and duration.
	CreateToken(email string, duration time.Duration) (string, *Payload, error)
	// VerifyToken checks if the token is valid and returns the email if it is.
	VerifyToken(token string) (*Payload, error)
	// VerifyIDToken checks if the IDToken is valid and returns the email if it is.
	VerifyIDToken(token string) (*IDTokenPayload, error)
	// VerifyAccessToken checks if the AccessToken is valid and returns the email if it is.
	VerifyAccessToken(token string) (*AccessTokenPayload, error)
	//CreateIDToken creates a new IDToken for the given request.
	CreateIDToken(issuer string, subject string, audience []string, duration time.Duration) (string, *IDTokenPayload, error)
	// Jwks returns the JSON Web Key Set (JWKS)
	Jwks() map[string]interface{}
}
