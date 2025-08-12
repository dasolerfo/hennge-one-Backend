package api

import (
	"github.com/gin-gonic/gin"
)

func NewServer() {
	router := gin.Default()

	router.GET("/login", DisplayLoginPage)
}
