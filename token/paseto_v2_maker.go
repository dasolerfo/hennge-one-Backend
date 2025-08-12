package token

import (
	"fmt"
	"time"

	"github.com/aead/chacha20poly1305"
	"github.com/o1egl/paseto"
)

type PasetoMaker struct {
	paseto       *paseto.V2
	symmetricKey []byte
}

// CreateToken implements Maker.
func (p *PasetoMaker) CreateToken(email string, duration time.Duration) (string, *Payload, error) {
	payload, err := NewPayload(email, duration)
	if err != nil {
		return "", payload, err
	}
	token, err := p.paseto.Encrypt(p.symmetricKey, payload, nil)

	return token, payload, err
}

// VerifyToken implx	ements Maker.
func (p *PasetoMaker) VerifyToken(token string) (*Payload, error) {
	payload := &Payload{}
	err := p.paseto.Decrypt(token, p.symmetricKey, payload, nil)
	if err != nil {
		return nil, InvalidTokenError
	}

	err = payload.Valid()
	if err != nil {
		return nil, ExpiredTokenError
	}

	return payload, nil
}

func NewPasetoMaker(symmetricKey string) (Maker, error) {
	if len(symmetricKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size! must be %d characters", chacha20poly1305.KeySize)
	}

	maker := &PasetoMaker{
		paseto:       paseto.NewV2(),
		symmetricKey: []byte(symmetricKey),
	}

	return maker, nil
}
