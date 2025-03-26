package controller

import (
	"adaptive-mfa/domain"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	appError "adaptive-mfa/pkg/error"
	"context"
	"crypto/sha1"
	"errors"
)

//go:generate mockgen -source=logout.go -destination=./mock/logout.go -package=mock
type ILogoutController interface {
	Logout(context.Context) (*domain.LogoutResponse, error)
}

type LogoutController struct {
	cache cache.ICache
}

func NewLogoutController(cache cache.ICache) ILogoutController {
	return &LogoutController{
		cache: cache,
	}
}

func (h *LogoutController) Logout(ctx context.Context) (*domain.LogoutResponse, error) {
	token := common.GetHeaders(ctx).Get("Authorization")
	if token == "" {
		return nil, appError.ErrorUnauthorized
	}

	sha1Token := string(sha1.New().Sum([]byte(token)))
	if err := h.cache.Del(ctx, cache.GetTokenKey(sha1Token)); err != nil {
		if errors.Is(err, cache.Nil) {
			return nil, appError.ErrorUnauthorized
		}
		return nil, appError.WithAppError(err, appError.CodeCacheError)
	}

	return &domain.LogoutResponse{}, nil
}
