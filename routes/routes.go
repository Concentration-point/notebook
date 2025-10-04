package routes

import (
	"github.com/Concentration-point/notebook/handlers"
	"github.com/Concentration-point/notebook/middleware"
	"github.com/gin-gonic/gin"
)

func SetUpRouter() *gin.Engine {
	r := gin.Default()

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
