package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTMaker struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      uuid.UUID
}

func NewJWTMaker(bits int) (*JWTMaker, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	maker := &JWTMaker{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      uuid.New(),
	}

	return maker, nil
}

// CreateToken creates a new JWT token for the given email and duration.
func (maker *JWTMaker) CreateToken(email string, duration time.Duration) (string, *AccessTokenPayload, error) {
	payload, err := NewPayload(email, duration)
	if err != nil {
		return "", payload, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, payload)
	token.Header["kid"] = maker.keyID // molt important per JWKS

	signed, err := token.SignedString(maker.privateKey)

	return signed, payload, err

}

// CreateToken creates a new JWT token for the given email and duration.
func (maker *JWTMaker) CreateIDToken(issuer string, subject string, audience []string, auth_time int64, duration time.Duration) (string, *IDTokenPayload, error) {

	payload, err := NewIDTokenPayLoad(issuer, subject, audience, auth_time, duration)
	if err != nil {
		return "", payload, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, payload)
	token.Header["kid"] = maker.keyID // molt important per JWKS

	signed, err := token.SignedString(maker.privateKey)

	return signed, payload, err

}

// VerifyToken checks if the JWT token is valid and returns the payload if it is.
func (maker *JWTMaker) VerifyToken(token string) (*Payload, error) {
	funcioKey := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
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
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
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
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
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
	n := base64.RawURLEncoding.EncodeToString(maker.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(maker.publicKey.E)).Bytes())

	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": maker.keyID,
		"n":   n,
		"e":   e,
	}

	return map[string]interface{}{
		"keys": []interface{}{jwk},
	}
}
