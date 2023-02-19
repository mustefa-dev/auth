package auth

import (
	"net/http"
	"strings"
)

func GetTokenFromHeader(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// The Authorization header has the format "Bearer <JWT-Token>"
	tokenString := strings.Split(authHeader, " ")[1]
	return tokenString
}
