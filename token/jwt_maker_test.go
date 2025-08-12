package token

import (
	"simplebank/factory"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestJWTMaker(t *testing.T) {
	// Create a new JWT maker
	maker, err := NewJWTMaker(factory.RandomString(32)) // Ensure the key is at least 32 characters
	require.NoError(t, err)

	// Test token creation and verification
	email := factory.RandomString(32)
	duration := time.Minute

	issuedAt := time.Now()
	expiredAt := issuedAt.Add(duration)

	token, payload, err := maker.CreateToken(email, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, payload)

	payload, err = maker.VerifyToken(token)
	require.NoError(t, err)
	require.NotEmpty(t, payload)
	require.NotZero(t, payload.ID)
	require.Equal(t, email, payload.Email)
	require.WithinDuration(t, issuedAt, payload.IssuedAt, time.Second)
	require.WithinDuration(t, expiredAt, payload.ExpiredAt, time.Second)

	if payload.Email != email {
		t.Errorf("Expected email %s, got %s", email, payload.Email)
	}
}

func TestExpiredJWTToken(t *testing.T) {
	// Create a new JWT maker
	maker, err := NewJWTMaker(factory.RandomString(32)) // Ensure the key is at least 32 characters
	require.NoError(t, err)

	// Test token creation with a short duration
	email := factory.RandomString(32)
	duration := -time.Minute // Negative duration to simulate expiration

	token, payload, err := maker.CreateToken(email, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, payload)

	// Verify the expired token
	payload, err = maker.VerifyToken(token)
	require.Error(t, err)
	require.Nil(t, payload)
	require.EqualError(t, err, ExpiredTokenError.Error())
}

func TestInvalidJWTToken(t *testing.T) {
	// Create a new JWT maker
	maker, err := NewJWTMaker(factory.RandomString(32)) // Ensure the key is at least 32 characters
	require.NoError(t, err)

	// Test with an invalid token
	invalidToken := "this.is.an.invalid.token"

	payload, err := maker.VerifyToken(invalidToken)
	require.Error(t, err)
	require.Nil(t, payload)
	require.EqualError(t, err, InvalidTokenError.Error())
}

func TestInvalidJWTAlgNoneToken(t *testing.T) {
	// Create a new JWT maker
	maker, err := NewJWTMaker(factory.RandomString(32)) // Ensure the key is at least 32 characters
	require.NoError(t, err)

	// Create a token with "none" algorithm
	payload, err := NewPayload(factory.RandomString(32), time.Minute)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodNone, payload)
	signedToken, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType) // No secret key for "none" algorithm
	require.NoError(t, err)

	// Verify the token
	payload, err = maker.VerifyToken(signedToken)
	require.Error(t, err)
	require.EqualError(t, err, InvalidTokenError.Error())
	require.Nil(t, payload)
}
