package controller

import (
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"adaptive-mfa/config"
	"adaptive-mfa/domain"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/ptr"
	"adaptive-mfa/repository"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type ILoginController interface {
	Login(w http.ResponseWriter, r *http.Request)
}

type LoginController struct {
	cfg            *config.Config
	cache          cache.ICache
	userRepository repository.IUserRepository
}

func NewLoginController(
	cfg *config.Config,
	cache cache.ICache,
	userRepository repository.IUserRepository,
) ILoginController {
	return &LoginController{
		cfg:            cfg,
		cache:          cache,
		userRepository: userRepository,
	}
}

func (h *LoginController) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.userRepository.GetByUsername(ctx, request.Username)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashPassword), []byte(request.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	exp := time.Now().Add(time.Hour * 24)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": exp.Unix(),
	}).SignedString([]byte(h.cfg.Jwt))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sha1Token := string(sha1.New().Sum([]byte(token)))
	if err := h.cache.Set(ctx, cache.GetTokenKey(sha1Token), fmt.Sprintf("%d", exp.UnixMilli()), ptr.ToPtr(time.Hour*24)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}
