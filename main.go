package main

import (
	_ "fmt"

	"github.com/Concentration-point/notebook/config"
	"github.com/Concentration-point/notebook/routes"
)

func main() {
	// 初始化数据库
	config.InitDB()

	// 创建Gin路由实例
	r := routes.SetUpRouter()

	r.Run(":8080")
}
