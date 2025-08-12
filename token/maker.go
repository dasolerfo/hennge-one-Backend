package token

import "time"

type Maker interface {
	// CreateToken creates a new token for the given email and duration.
	CreateToken(email string, duration time.Duration) (string, *Payload, error)

	// VerifyToken checks if the token is valid and returns the email if it is.
	VerifyToken(token string) (*Payload, error)
}
