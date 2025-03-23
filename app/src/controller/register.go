package controller

import (
	"encoding/json"
	"net/http"

	"adaptive-mfa/model"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/database"
	"adaptive-mfa/repository"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type IRegisterController interface {
	Register(w http.ResponseWriter, r *http.Request)
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

type RegisterRequest struct {
	Fullname string `json:"fullname"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
}

func (h *RegisterController) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), 14)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newUser := model.User{
		ID:           uuid.New().String(),
		Fullname:     request.Fullname,
		Username:     request.Username,
		HashPassword: string(hashPassword),
		Email:        database.NewNullString(request.Email),
		Phone:        database.NewNullString(request.Phone),
	}

	if err := h.userRepository.Create(ctx, &newUser); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
