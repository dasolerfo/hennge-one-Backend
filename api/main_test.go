package api

import (
	"os"

	"testing"
	"time"

	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/dasolerfo/hennge-one-Backend.git/help"
	"github.com/gin-gonic/gin"
)

func NewTestServer(t *testing.T, store db.Store) *Server {
	config := help.Config{
		TokenSymmetricKey: help.RandomString(32),
		TokenDuration:     15 * time.Minute,
		SymmetricKeyBits:  2048,
		SessionKey:        help.RandomString(32),
	}

	server, err := NewServer(&config, &store)
	if err != nil {
		t.Fatal("Error! No es pot inicialitzar el server: ", err)
	}

	return server
}
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}
