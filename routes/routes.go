package routes

import (
	_ "github.com/Concentration-point/notebook/docs" // 引入生成的docs包
	"github.com/Concentration-point/notebook/handlers"
	"github.com/Concentration-point/notebook/middleware"
	"github.com/gin-gonic/gin"
	// swaggerFiles "github.com/swaggo/files"
	// ginSwagger "github.com/swaggo/gin-swagger"
)

func SetUpRouter() *gin.Engine {
	r := gin.Default()

	// // Swagger 路由
	// r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	public := r.Group("/api")
	{
		public.POST("/register", handlers.Register)
		public.POST("/login", handlers.Login)
	}

	// 需要认证的路由

	protected := r.Group("/api")
	protected.Use(middleware.AuthMiddleware())
	{
		protected.GET("/notes", handlers.GetNotes)
		protected.GET("/notes/:id", handlers.GetNote)
		protected.POST("/notes", handlers.CreateNote)
		protected.PUT("/notes/:id", handlers.UpdateNote)
		protected.DELETE("/notes/:id", handlers.DeleteNote)
	}

	return r

}
