package main

import (
	"github.com/gin-gonic/gin"
	"jwt/controllers"
	"jwt/models"
)

func main() {
	// Connect to the database
	models.ConnectDatabase()

	// Initialize the router
	router := gin.Default()

	// Define the registration and login endpoints
	router.POST("/register", controllers.Register)
	router.POST("/login", controllers.Login)

	// Start the server
	router.Run(":8080")
}
