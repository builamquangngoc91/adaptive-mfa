package controller

import (
	"adaptive-mfa/pkg/cache"
	"crypto/sha1"
	"net/http"
)

type ILogoutController interface {
	Logout(w http.ResponseWriter, r *http.Request)
}

type LogoutController struct {
	cache cache.ICache
}

func NewLogoutController(cache cache.ICache) ILogoutController {
	return &LogoutController{
		cache: cache,
	}
}

func (h *LogoutController) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sha1Token := string(sha1.New().Sum([]byte(token)))
	if err := h.cache.Del(ctx, cache.GetTokenKey(sha1Token)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
