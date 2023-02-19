package auth

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

func CheckRole(requiredRole string, secretKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := GetTokenFromHeader(r)
			if tokenString == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(secretKey), nil
			})
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok || !token.Valid {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			role, ok := claims["role"].(string)
			if !ok || role != requiredRole {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
