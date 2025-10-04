package main

import (
	_ "fmt"

	"github.com/gin-gonic/gin"
)

func main() {

	// 创建Gin路由实例
	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "收到",
		})
	})

	r.Run(":8080")
}
