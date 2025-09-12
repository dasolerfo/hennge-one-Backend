package token

import (
	"testing"
	"time"

	"github.com/dasolerfo/hennge-one-Backend.git/help"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestJWTMaker(t *testing.T) {
	// Create a new JWT maker
	maker, err := NewJWTMaker(int(help.RandomInt(1024, 2048))) // Ensure the key is at least 32 characters
	require.NoError(t, err)

	// Test token creation and verification
	email := help.RandomString(32)
	duration := time.Minute

	issuedAt := time.Now()
	expiredAt := issuedAt.Add(duration)

	token, payload, err := maker.CreateToken(email, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, payload)

	payload, err = maker.VerifyAccessToken(token)
	require.NoError(t, err)
	require.NotEmpty(t, payload)
	//require.NotZero(t, payload.Issuer)
	//require.NotZero(t, payload.Subject)

	//require.Equal(t, email, payload.Email)
	require.WithinDuration(t, issuedAt, time.Unix(payload.IssuedAt, 0).UTC(), time.Second)
	require.WithinDuration(t, expiredAt, time.Unix(payload.ExpiredAt, 0).UTC(), time.Second)

	/*if payload.Email != email {
		t.Errorf("Expected email %s, got %s", email, payload.Email)
	}*/
}

func TestExpiredJWTToken(t *testing.T) {
	// Create a new JWT maker
	maker, err := NewJWTMaker(int(help.RandomInt(1024, 2048))) // Ensure the key is at least 32 characters
	require.NoError(t, err)

	// Test token creation with a short duration
	email := help.RandomString(32)
	duration := -time.Minute // Negative duration to simulate expiration

	token, payload, err := maker.CreateToken(email, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, payload)

	// Verify the expired token
	payload, err = maker.VerifyAccessToken(token)
	require.Error(t, err)
	require.Nil(t, payload)
	require.EqualError(t, err, ExpiredTokenError.Error())
}

func TestInvalidJWTToken(t *testing.T) {
	// Create a new JWT maker
	maker, err := NewJWTMaker(int(help.RandomInt(1024, 2048))) // Ensure the key is at least 32 characters
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
	maker, err := NewJWTMaker(int(help.RandomInt(1024, 2048))) // Ensure the key is at least 32 characters
	require.NoError(t, err)

	// Create a token with "none" algorithm
	payload, err := NewPayload(help.RandomString(32), time.Minute)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodNone, payload)
	signedToken, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType) // No secret key for "none" algorithm
	require.NoError(t, err)

	// Verify the token
	payload, err = maker.VerifyAccessToken(signedToken)
	require.Error(t, err)
	require.EqualError(t, err, InvalidTokenError.Error())
	require.Nil(t, payload)
}

func TestJWTIDToken(t *testing.T) {
	// Create a new JWT maker
	maker, err := NewJWTMaker(int(help.RandomInt(1024, 2048))) // Ensure the key is at least 32 characters
	require.NoError(t, err)

	// Test token creation and verification
	issuer := "test_issuer"
	subject := "test_subject"
	audience := []string{"test_audience"}
	duration := time.Minute

	issuedAt := time.Now()
	expiredAt := issuedAt.Add(duration)

	token, payload, err := maker.CreateIDToken(issuer, subject, audience, issuedAt.Unix(), duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, payload)

	payload, err = maker.VerifyIDToken(token)
	require.NoError(t, err)
	require.NotEmpty(t, payload)
	//require.NotZero(t, payload.ID) --- IGNORE ---
	require.Equal(t, subject, payload.Subject)
	require.WithinDuration(t, issuedAt, time.Unix(payload.IssuedAt, 0).UTC(), time.Second)
	require.WithinDuration(t, expiredAt, time.Unix(payload.ExpiredAt, 0).UTC(), time.Second)

}
