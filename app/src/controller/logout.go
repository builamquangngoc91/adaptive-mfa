package controller

import (
	"adaptive-mfa/domain"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"context"
	"crypto/sha1"
	"errors"
)

//go:generate mockgen -source=logout.go -destination=./mock/logout.go -package=mock
type ILogoutController interface {
	Logout(context.Context, *domain.LogoutRequest) (*domain.LogoutResponse, error)
}

type LogoutController struct {
	cache cache.ICache
}

func NewLogoutController(cache cache.ICache) ILogoutController {
	return &LogoutController{
		cache: cache,
	}
}

func (h *LogoutController) Logout(ctx context.Context, req *domain.LogoutRequest) (*domain.LogoutResponse, error) {
	token := common.GetHeaders(ctx).Get("Authorization")
	if token == "" {
		return nil, errors.New("Unauthorized")
	}

	sha1Token := string(sha1.New().Sum([]byte(token)))
	if err := h.cache.Del(ctx, cache.GetTokenKey(sha1Token)); err != nil {
		return nil, err
	}

	return &domain.LogoutResponse{}, nil
}
