package api

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/dasolerfo/hennge-one-Backend.git/help"
	"github.com/dasolerfo/hennge-one-Backend.git/token"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/acme/autocert"
)

type Server struct {
	Config     help.Config
	tokenMaker token.Maker
	store      db.Store
	router     *gin.Engine
}

func NewServer(config *help.Config, store *db.Store) (*Server, error) {
	tokenMaker, err := token.NewJWTMaker(config.SymmetricKeyBits)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker: %v", err)
	}

	server := &Server{
		tokenMaker: tokenMaker,
		Config:     *config,
		store:      *store,
	}

	server.Router()

	return server, nil

}

func (server *Server) Router() {
	router := gin.Default()
	router.LoadHTMLGlob("./templates/*")

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

	router.GET("/well-known/openid-configuration", server.DiscoveryGetHandler)
	router.GET("/initiate_login_uri", server.InitiateLoginHandler)
	router.GET("/.well-known/jwks.json", server.JwksGetHandler)
	router.GET("/userinfo", server.UserinfoGetHandler)
	router.POST("/userinfo", server.UserinfoGetHandler)

	server.router = router

}

func (server *Server) Start() {
	if server.Config.RunMode == "local" {
		RunLocal(server.router)
	} else {
		//RunRemote(server.router)
		RunEC2(server.router)
	}
}

func RunLocal(router *gin.Engine) {

	// Configuració del servidor amb TLS
	srv := &http.Server{
		Addr:    ":8443",
		Handler: router,
	}

	log.Println("Servidor HTTPS escoltant a https://localhost:8443")
	log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))

}

func RunRemote(router *gin.Engine) {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("certs"), // carpeta on guarda els certificats
		HostPolicy: autocert.HostWhitelist("idp.danisoler.com"),
	}

	srv := &http.Server{
		Addr:    ":443",
		Handler: router,
		TLSConfig: &tls.Config{
			GetCertificate: m.GetCertificate,
		},
	}
	// Servidor HTTP per validació Let's Encrypt
	go func() {
		log.Fatal(http.ListenAndServe(":80", m.HTTPHandler(nil)))
	}()

	log.Fatal(srv.ListenAndServeTLS("", ""))

}

func RunEC2(router *gin.Engine) {
	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	log.Println("Servidor HTTP escoltant a http://0.0.0.0:8080")
	log.Fatal(srv.ListenAndServe())

}
