package api

import "github.com/gin-gonic/gin"

func DisplayLoginPage(c *gin.Context) {
	c.HTML(200, "login.html", gin.H{})
}
