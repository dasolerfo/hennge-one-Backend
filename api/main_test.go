package api

import (
	"fmt"
	"os"

	"testing"
	"time"

	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/dasolerfo/hennge-one-Backend.git/help"
	"github.com/dasolerfo/hennge-one-Backend.git/token"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func NewTestServer(t *testing.T, store db.Store) *Server {
	config := help.Config{
		TokenSymmetricKey: help.RandomString(32),
		TokenDuration:     15 * time.Minute,
		SymmetricKeyBits:  2048,
		SessionKey:        help.RandomString(32),
	}

	server, err := NewServerWithoutTemplates(&config, &store)
	if err != nil {
		t.Fatal("Error! No es pot inicialitzar el server: ", err)
	}

	return server
}
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

func NewServerWithoutTemplates(config *help.Config, store *db.Store) (*Server, error) {
	tokenMaker, err := token.NewJWTMaker(config.SymmetricKeyBits)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker: %v", err)
	}

	server := &Server{
		tokenMaker: tokenMaker,
		Config:     *config,
		store:      *store,
	}

	server.RouterTest()

	return server, nil

}

func (server *Server) RouterTest() {
	router := gin.Default()

	store := cookie.NewStore([]byte(server.Config.SessionKey))
	router.Use(sessions.Sessions("session_active", store))

	router.GET("/", func(r *gin.Context) {
		r.JSON(200, gin.H{"hello": "Si reps això desde el Postmant, funciona!"})
	})

	router.POST("/create_user", server.CreateUserHandler)
	router.GET("/authorize", server.AuthorizeGetHandler)

	// OAuth2 endpointss
	router.POST("/token", server.TokenPostHandler)
	router.GET("/login", server.DisplayLoginPage)
	router.POST("/login", server.LoginPostHandler)

	router.POST("/register_client", server.RegisterClientHandler)
	router.GET("/clients", server.ClientsGetHandler)
	router.POST("/permissions", server.PermissionPostHandler)

	// OIDC endpoints

	router.GET("/.well-known/openid-configuration", server.DiscoveryGetHandler)
	router.GET("/initiate_login_uri", server.InitiateLoginHandler)
	router.GET("/.well-known/jwks.json", server.JwksGetHandler)
	router.GET("/userinfo", server.UserinfoGetHandler)
	router.POST("/userinfo", server.UserinfoGetHandler)

	server.router = router

}
