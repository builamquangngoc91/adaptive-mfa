package controller

import (
	"adaptive-mfa/config"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/common"
	"context"
	"errors"
)

type IHackedController interface {
	Disavow(ctx context.Context, req any) (any, error)
}

type HackedController struct {
	cfg   *config.Config
	cache cache.ICache
}

func NewHackedController(cfg *config.Config, cache cache.ICache) IHackedController {
	return &HackedController{
		cfg:   cfg,
		cache: cache,
	}
}

func (h *HackedController) Disavow(ctx context.Context, req any) (any, error) {
	referenceID := common.GetParams(ctx).Get("ref")

	// TODO: Save the reference ID to the database
	if referenceID == "" {
		return nil, errors.New("reference ID is required")
	}

	if err := h.cache.Del(ctx, cache.GetMFAReferenceIDKey(referenceID)); err != nil {
		return nil, err
	}

	return "Disavow OK", nil
}
