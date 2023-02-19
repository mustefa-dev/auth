package main

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"jwt/controllers"
	_ "jwt/docs"
	"jwt/models"
	"net/http"
)

// @title JWT Auth API
// @description This is a sample JWT authentication API.
// @version 1
// @host localhost:8080
// @BasePath /
func main() {
	// Connect to the database
	models.ConnectDatabase()

	r := gin.Default()

	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Register and login endpoints
	r.POST("/register", controllers.Register)
	r.POST("/login", controllers.Login)

	// JWT authentication middleware
	authMiddleware := controllers.AuthMiddleware

	// Auth middleware
	auth := r.Group("/auth")
	auth.Use(authMiddleware)
	{
		auth.GET("/", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "authorized"})
		})
	}

	// User endpoints
	users := r.Group("/users")
	users.Use(authMiddleware)
	{
		// Requires JWT authentication and "Admin" role
		// @Security ApiKeyAuth
		users.GET("/:id", controllers.GetUser)
	}

	r.Run(":8080")
}
