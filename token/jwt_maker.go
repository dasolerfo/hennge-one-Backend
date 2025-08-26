package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTMaker struct {
	secretKey string
}

const minKeySize = 32 // Minimum key size for HMAC-SHA256

// NewJWTMaker creates a new JWTMaker with the provided secret key.
func NewJWTMaker(secretKey string) (Maker, error) {
	if len(secretKey) < minKeySize {
		return nil, fmt.Errorf("invalid key size: must be at least %d characters", minKeySize)
	}
	return &JWTMaker{secretKey: secretKey}, nil
}

// CreateToken creates a new JWT token for the given email and duration.
func (maker *JWTMaker) CreateToken(email string, duration time.Duration) (string, *Payload, error) {
	payload, err := NewPayload(email, duration)
	if err != nil {
		return "", payload, err
	}
	jwttoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	token, err := jwttoken.SignedString([]byte(maker.secretKey))
	return token, payload, err

}

// CreateToken creates a new JWT token for the given email and duration.
func (maker *JWTMaker) CreateIDToken(issuer string, subject string, audience []string, duration time.Duration) (string, *IDTokenPayload, error) {

	payload, err := NewIDTokenPayLoad(issuer, subject, audience, duration)
	if err != nil {
		return "", payload, err
	}
	jwttoken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	token, err := jwttoken.SignedString([]byte(maker.secretKey))
	return token, payload, err

}

// VerifyToken checks if the JWT token is valid and returns the payload if it is.
func (maker *JWTMaker) VerifyToken(token string) (*Payload, error) {
	funcioKey := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, InvalidTokenError
		}

		return []byte(maker.secretKey), nil
	}

	jwtToken, err := jwt.ParseWithClaims(token, &Payload{}, funcioKey)

	if err != nil {
		// Check if the error is due to an expired token
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ExpiredTokenError
		}
		return nil, InvalidTokenError
	}
	payload, ok := jwtToken.Claims.(*Payload)
	if !ok {
		return nil, InvalidTokenError
	}
	return payload, nil

}

// VerifyToken checks if the JWT token is valid and returns the payload if it is.
func (maker *JWTMaker) VerifyIDToken(token string) (*IDTokenPayload, error) {
	funcioKey := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, InvalidTokenError
		}
		return []byte(maker.secretKey), nil
	}

	jwtToken, err := jwt.ParseWithClaims(token, &IDTokenPayload{}, funcioKey)

	if err != nil {
		// Check if the error is due to an expired token
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ExpiredTokenError
		}
		return nil, InvalidTokenError
	}
	payload, ok := jwtToken.Claims.(*IDTokenPayload)
	if !ok {
		return nil, InvalidTokenError
	}
	return payload, nil

}

func (maker *JWTMaker) VerifyAccessToken(token string) (*AccessTokenPayload, error) {
	funcioKey := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, InvalidTokenError
		}
		return []byte(maker.secretKey), nil
	}

	jwtToken, err := jwt.ParseWithClaims(token, &AccessTokenPayload{}, funcioKey)

	if err != nil {
		// Check if the error is due to an expired token
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ExpiredTokenError
		}
		return nil, InvalidTokenError
	}
	payload, ok := jwtToken.Claims.(*AccessTokenPayload)
	if !ok {
		return nil, InvalidTokenError
	}
	return payload, nil

}

// Jwks returns the JSON Web Key Set (JWKS)
func (maker *JWTMaker) Jwks() map[string]interface{} {
	jwks := make(map[string]interface{})
	jwks["keys"] = []map[string]string{
		{
			"kty": "oct",
			"use": "sig",
			"alg": "HS256",
			"k":   maker.secretKey,
		},
	}
	return jwks
}
