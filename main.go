package main

import (
	_ "fmt"

	"github.com/Concentration-point/notebook/config"
	"github.com/Concentration-point/notebook/routes"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title 记事本 API
// @version 1.0
// @description 这是一个基于 Go + Gin + MySQL 的简单记事本项目 API 文档
// @termsOfService http://example.com/terms/

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /
// @schemes http
func main() {
	// 初始化数据库
	config.InitDB()

	// 创建Gin路由实例
	r := routes.SetUpRouter()

	// 集成swaager
	url := ginSwagger.URL("http://localhost:8080/swagger/doc.json")
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, url))

	r.Run(":8080")
}
