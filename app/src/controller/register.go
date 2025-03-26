package controller

import (
	"context"

	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/database"
	"adaptive-mfa/repository"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

//go:generate mockgen -source=register.go -destination=./mock/register.go -package=mock
type IRegisterController interface {
	Register(context.Context, *domain.RegisterRequest) (*domain.RegisterResponse, error)
}

type RegisterController struct {
	cache          cache.ICache
	userRepository repository.IUserRepository
}

func NewRegisterController(cache cache.ICache, userRepository repository.IUserRepository) IRegisterController {
	return &RegisterController{
		cache:          cache,
		userRepository: userRepository,
	}
}

func (h *RegisterController) Register(ctx context.Context, req *domain.RegisterRequest) (*domain.RegisterResponse, error) {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), 14)
	if err != nil {
		return nil, err
	}

	newUser := model.User{
		ID:           uuid.New().String(),
		Fullname:     req.Fullname,
		Username:     req.Username,
		HashPassword: string(hashPassword),
		Email:        database.NewNullString(req.Email),
		Phone:        database.NewNullString(req.Phone),
	}

	if err := h.userRepository.Create(ctx, nil, &newUser); err != nil {
		return nil, err
	}

	return &domain.RegisterResponse{}, nil
}
