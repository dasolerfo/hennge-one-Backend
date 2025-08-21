package help

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateCode(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	// Base64 URL-safe
	return base64.RawURLEncoding.EncodeToString(b), nil
}
