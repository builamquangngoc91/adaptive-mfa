package controller

import (
	"adaptive-mfa/domain"
	"context"
)

type IHealthController interface {
	Health(ctx context.Context) (*domain.HealthResponse, error)
}

type HealthController struct{}

func NewHealthController() IHealthController {
	return &HealthController{}
}

func (c *HealthController) Health(ctx context.Context) (*domain.HealthResponse, error) {
	return &domain.HealthResponse{
		Status: "OK",
	}, nil
}
