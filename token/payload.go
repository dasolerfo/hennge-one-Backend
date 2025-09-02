package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ExpiredTokenError = errors.New("token has expired")
	InvalidTokenError = errors.New("invalid token")
)

type Payload struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiredAt int64  `json:"exp"`
}

type AccessTokenPayload struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`
	Payload
}

type IDTokenPayload struct {
	Payload
	AuthTime int64    `json:"auth_time"`
	Audience []string `json:"aud"`
}

// GetExpirationTime implements jwt.Claims.
func (p *Payload) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(p.ExpiredAt, 0).UTC()), nil

}

// GetIssuedAt implements jwt.Claims.
func (p *Payload) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(p.IssuedAt, 0).UTC()), nil
}

// GetIssuer implements jwt.Claims.
func (p *Payload) GetIssuer() (string, error) {
	if p == nil {
		return "", errors.New("payload is nil")
	}
	//return p.Email, nil
	return p.Issuer, nil
}

// GetNotBefore implements jwt.Claims.
func (p *Payload) GetNotBefore() (*jwt.NumericDate, error) {
	if p == nil {
		return nil, errors.New("payload is nil")
	}
	return jwt.NewNumericDate(time.Unix(p.IssuedAt, 0).UTC()), nil
}

// GetSubject implements jwt.Claims.
func (p *Payload) GetSubject() (string, error) {
	if p == nil {
		return "", errors.New("payload is nil")
	}
	/*if p.ID == uuid.Nil {
		return "", errors.New("payload ID is nil")
	}*/
	return p.Subject, nil

}

// NewPayload creates a new Payload with a unique ID, email, issued time, and expiration time.
// It returns an error if the UUID generation fails.
func NewPayload(email string, duration time.Duration) (*Payload, error) {
	/*id, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}*/

	payload := &Payload{
		//ID:        id,
		//Email:     email,
		IssuedAt:  int64(time.Now().UTC().Unix()),
		ExpiredAt: int64(time.Now().UTC().Add(duration).Unix()),
	}

	return payload, nil
}

func NewIDTokenPayLoad(issuer string, subject string, audience []string, auth_time int64, duration time.Duration) (*IDTokenPayload, error) {

	payload := &IDTokenPayload{
		Payload: Payload{
			Issuer:    issuer,
			Subject:   subject,
			IssuedAt:  int64(time.Now().UTC().Unix()),
			ExpiredAt: int64(time.Now().UTC().Add(duration).Unix()),
		},
		AuthTime: int64(time.Now().UTC().Unix()),
		Audience: audience,
	}
	return payload, nil
}

func (p *Payload) Valid() error {
	if time.Now().After(time.Unix(p.ExpiredAt, 0).UTC()) {
		return ExpiredTokenError
	}
	return nil
}

func (p *Payload) GetAudience() (jwt.ClaimStrings, error) {
	if p == nil {
		return nil, errors.New("payload is nil")
	}
	audience := jwt.ClaimStrings{}
	audience = append(audience, p.Issuer)
	return audience, nil
}
