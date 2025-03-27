package controller

import (
	"context"
	"database/sql"
	"errors"

	"adaptive-mfa/domain"
	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/database"
	appError "adaptive-mfa/pkg/error"
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
	if err := req.Validate(); err != nil {
		return nil, appError.WithAppError(err, appError.CodeBadRequest)
	}

	user, err := h.userRepository.GetByUsername(ctx, nil, req.Username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}
	if user != nil {
		return nil, appError.WithAppError(errors.New("username already exists"), appError.CodeBadRequest)
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), 14)
	if err != nil {
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
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
		return nil, appError.WithAppError(err, appError.CodeInternalServerError)
	}

	return &domain.RegisterResponse{}, nil
}
