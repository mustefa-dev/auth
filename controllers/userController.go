package controllers

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
	. "jwt/auth"
	. "jwt/models"
	"net/http"
	"os"
)

var SecretKey = "mysecretkey"

// Register @Summary Register a new user
// @Description Register a new user with the provided username and password
// @Accept json
// @Produce json
// @Param input body models.LoginRequest true "Registration details"
// @Success 201 {string} string "Successfully registered user"
// @Failure 400 {string} string "Invalid registration details"
// @Failure 500 {string} string "Server error"
// @Router /register [post]
func Register(c *gin.Context) {
	// Bind the request body to the User struct
	var user User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Check if user already exists
	db := GetDB()
	existingUser := User{}
	if err := db.Where("username = ?", user.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	// Create the user in the database
	user.Password = string(hashedPassword)
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating user"})
		return
	}

	// Return the created user
	c.JSON(http.StatusCreated, user)
}

// Login @Summary Login with username and password
// @Description Authenticate user with provided credentials and return JWT token
// @Accept json
// @Produce json
// @Param input body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.LoginRequest "JWT token"
// @Failure 400 {string} string "Invalid login credentials"
// @Failure 500 {string} string "Server error"
// @Router /login [post]
func Login(c *gin.Context) {
	// Bind the request body to the LoginRequest struct
	var loginRequest LoginRequest
	if err := c.BindJSON(&loginRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Find the user by username
	var user User
	db := GetDB()
	if err := db.Where("username = ?", loginRequest.Username).First(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error finding user"})
		return
	}

	// Check the password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginRequest.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Generate a JWT token
	token, err := GenerateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}

	// Return the token
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// AuthMiddleware is a Gin middleware that handles authentication using JSON Web Tokens (JWT).
//
// @Summary Authenticate user using JWT
// @Description Verify if the incoming request contains a valid JSON Web Token (JWT) in the "Authorization" header, extract the user ID from it, and set it in the context for subsequent requests to use.
// @Tags Authentication
// @Accept  json
// @Produce  json
// @Security ApiKeyAuth
//
// @Param Authorization header string true "JWT Token with 'Bearer ' prefix"
// @Success 200 {string} string "OK"
//
// @Router /auth [GET]
func AuthMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		c.Abort()
		return
	}
	tokenString := authHeader[len("Bearer "):]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Get the secret key
		secretKey := []byte(os.Getenv("JWT_SECRET_KEY"))
		return secretKey, nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}
	userID, ok := claims["userID"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}
	c.Set("userID", uint(userID))
	c.Next()
}

// GetUser @Summary Get a user by ID
// @Description Retrieve a user by ID
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} User
// @Failure 400 {string} string "Bad Request"
// @Failure 404 {string} string "User not found"
// @Router /users/{id} [get]
func GetUser(c *gin.Context) {
	userID, ok := c.Get("userID")
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in request context"})
		return
	}
	db := GetDB()
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}
