package middleware

import (
	"adaptive-mfa/config"
	cacheUtils "adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/repository"
	"adaptive-mfa/server"

	"context"
	"crypto/sha1"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func AuthMiddleware(
	cfg *config.Config,
	cache cacheUtils.ICache,
	userRepository repository.IUserRepository,
) server.Middleware {
	return func(next server.Handler) server.Handler {
		return func(w http.ResponseWriter, r *http.Request) {
			tokenStr := r.Header.Get("Authorization")
			sha1Token := string(sha1.New().Sum([]byte(tokenStr)))

			if _, err := cache.Get(r.Context(), cacheUtils.GetTokenKey(sha1Token)); err != nil {
				http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
				return
			}

			token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
				return []byte(cfg.Jwt), nil
			})
			if err != nil {
				http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok || !token.Valid {
				http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
				return
			}

			if exp := int64(claims["exp"].(float64)); exp < time.Now().Unix() {
				http.Error(w, "Unauthorized: Token expired", http.StatusUnauthorized)
				return
			}

			userID := claims["sub"].(string)
			user, err := userRepository.GetByID(r.Context(), nil, userID)
			if err != nil {
				http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
				return
			}

			if user == nil {
				http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
				return
			}

			newCtx := context.WithValue(r.Context(), common.ContextKeyUserID, user.ID)
			next(w, r.WithContext(newCtx))
		}
	}
}
