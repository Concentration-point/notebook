package config

import (
	"log"

	"github.com/Concentration-point/notebook/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	dsn := "root:Qyk880329/@tcp(127.0.0.1:3306)/notepad?charset=utf8mb4&parseTime=True&loc=Local"
	var err error

	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("数据库连接失败:", err)
	}

	// 根据 Go 结构体自动创建或更新数据库表结构。
	DB.AutoMigrate(&models.User{}, &models.Note{})
}
