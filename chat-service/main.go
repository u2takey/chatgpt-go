package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Cors() gin.HandlerFunc {
	return func(context *gin.Context) {
		method := context.Request.Method
		context.Header("Access-Control-Allow-Origin", "*")
		context.Header("Access-Control-Allow-Headers", "Content-Type, AccessToken, X-CSRF-Token, Authorization, Token")
		context.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		context.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Content-Type")
		context.Header("Access-Control-Allow-Credentials", "true")
		if method == "OPTIONS" {
			context.AbortWithStatus(http.StatusNoContent)
		}
		context.Next()
	}
}

func main() {
	r := gin.Default()
	r.Use(Cors())
	r.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})
	r.POST("/bind", func(c *gin.Context) {
		req := &BindBotRequest{}
		err := c.BindJSON(req)
		if err != nil {
			c.JSON(200, CommonResponse{400, err.Error()})
		} else {
			c.JSON(200, BindBot(c, req))
		}
	})
	r.POST("/ask", func(c *gin.Context) {
		req := &AskRequest{}
		err := c.BindJSON(req)
		if err != nil {
			c.JSON(200, CommonResponse{400, err.Error()})
		} else {
			c.JSON(200, Ask(c, req))
		}
	})
	log.Fatal(r.Run(":8088"))
}
