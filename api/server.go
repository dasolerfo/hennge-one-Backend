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

	router.GET("/authorize")
	router.POST("/authorize")
	router.GET("/token")
	router.POST("/token")
	router.GET("/login", DisplayLoginPage)

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
