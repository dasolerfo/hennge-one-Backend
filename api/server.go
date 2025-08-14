package api

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/acme/autocert"
)

func NewServer() {
	router := gin.Default()

	router.GET("/", func(r *gin.Context) {
		r.JSON(200, gin.H{"hello": "Si reps això desde el Postmant, funciona!"})
	})

	router.GET("/authorize")
	router.POST("/authorize")
	router.GET("/token")
	router.POST("/token")
	router.GET("/login", DisplayLoginPage)

	RunLocal(router)
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
