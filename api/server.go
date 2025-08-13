package api

import (
	"github.com/gin-gonic/gin"
)

func NewServer() {
	router := gin.Default()

	router.GET("/autherize")
	router.POST("/autherize")
	router.GET("/token")
	router.POST("/token")
	router.GET("/login", DisplayLoginPage)
}
